from logging import getLogger
from typing import Optional

from django.db import router, transaction
from django.db.models import F, Q, Sum, Value
from django.db.models.functions import Concat
from django.utils import timezone

from axes.attempts import (
    clean_expired_user_attempts,
    get_user_attempts,
    reset_user_attempts,
)
from axes.conf import settings
from axes.handlers.base import AxesBaseHandler, AbstractAxesHandler
from axes.helpers import (
    get_client_session_hash,
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_lockout_parameters,
    get_query_str,
)
from axes.models import AccessLog, AccessAttempt, AccessFailureLog
from axes.signals import user_locked_out

log = getLogger(__name__)


class AxesDatabaseHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.

    .. note:: The get_user_attempts function is called several time during the authentication and lockout
              process, caching its output can be dangerous.
    """

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        attempts = AccessAttempt.objects.all()

        if ip_or_username:
            attempts = attempts.filter(Q(ip_address=ip_address) | Q(username=username))
        else:
            if ip_address:
                attempts = attempts.filter(ip_address=ip_address)
            if username:
                attempts = attempts.filter(username=username)

        count, _ = attempts.delete()
        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    def reset_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessLog.objects.all().delete()
            log.info("AXES: Reset all %d access logs from database.", count)
        else:
            limit = timezone.now() - timezone.timedelta(days=age_days)
            count, _ = AccessLog.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def reset_failure_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessFailureLog.objects.all().delete()
            log.info("AXES: Reset all %d access failure logs from database.", count)
        else:
            limit = timezone.now() - timezone.timedelta(days=age_days)
            count, _ = AccessFailureLog.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access failure logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def remove_out_of_limit_failure_logs(
        self,
        *,
        username: str,
        limit: Optional[int] = settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT,
    ) -> int:
        count = 0
        failures = AccessFailureLog.objects.filter(username=username)
        out_of_limit_failures_logs = failures.count() - limit
        if out_of_limit_failures_logs > 0:
            for failure in failures[:out_of_limit_failures_logs]:
                failure.delete()
                count += 1
        return count

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        attempts_list = get_user_attempts(request, credentials)
        attempt_count = max(
            (
                attempts.aggregate(Sum("failures_since_start"))[
                    "failures_since_start__sum"
                ]
                or 0
            )
            for attempts in attempts_list
        )
        return attempt_count

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """When user login fails, save AccessFailureLog record in database,
        save AccessAttempt record in database, mark request with
        lockout attribute and emit lockout signal.

        """

        log.info("AXES: User login failed, running database handler for failure.")

        if request is None:
            log.error(
                "AXES: AxesDatabaseHandler.user_login_failed does not function without a request."
            )
            return

        # 1. database query: Clean up expired user attempts from the database before logging new attempts
        clean_expired_user_attempts(request.axes_attempt_time)

        username = get_client_username(request, credentials)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        # If axes denied access, don't record the failed attempt as that would reset the lockout time.
        if (
            not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT
            and request.axes_locked_out
        ):
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )
            return

        # This replaces null byte chars that crash saving failures.
        get_data = get_query_str(request.GET).replace("\0", "0x00")
        post_data = get_query_str(request.POST).replace("\0", "0x00")

        if self.is_whitelisted(request, credentials):
            log.info("AXES: Login failed from whitelisted client %s.", client_str)
            return

        # 2. database query: Get or create access record with the new failure data
        lockout_parameters = get_lockout_parameters(request, credentials)
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
        else:
            with transaction.atomic(using=router.db_for_write(AccessAttempt)):
                (
                    attempt,
                    created,
                ) = AccessAttempt.objects.select_for_update().get_or_create(
                    username=username,
                    ip_address=request.axes_ip_address,
                    user_agent=request.axes_user_agent,
                    defaults={
                        "get_data": get_data,
                        "post_data": post_data,
                        "http_accept": request.axes_http_accept,
                        "path_info": request.axes_path_info,
                        "failures_since_start": 1,
                        "attempt_time": request.axes_attempt_time,
                    },
                )

                # Record failed attempt with all the relevant information.
                # Filtering based on username, IP address and user agent handled elsewhere,
                # and this handler just records the available information for further use.
                if created:
                    log.warning(
                        "AXES: New login failure by %s. Created new record in the database.",
                        client_str,
                    )

                # 3. database query if there were previous attempts in the database
                # Update failed attempt information but do not touch the username, IP address, or user agent fields,
                # because attackers can request the site with multiple different configurations
                # in order to bypass the defense mechanisms that are used by the site.
                else:
                    separator = "\n---------\n"

                    attempt.get_data = Concat("get_data", Value(separator + get_data))
                    attempt.post_data = Concat(
                        "post_data", Value(separator + post_data)
                    )
                    attempt.http_accept = request.axes_http_accept
                    attempt.path_info = request.axes_path_info
                    attempt.failures_since_start = F("failures_since_start") + 1
                    attempt.attempt_time = request.axes_attempt_time
                    attempt.save()

                    log.warning(
                        "AXES: Repeated login failure by %s. Updated existing record in the database.",
                        client_str,
                    )

        # 3. or 4. database query: Calculate the current maximum failure number from the existing attempts
        failures_since_start = self.get_failures(request, credentials)
        request.axes_failures_since_start = failures_since_start

        if (
            settings.AXES_LOCK_OUT_AT_FAILURE
            and failures_since_start >= get_failure_limit(request, credentials)
        ):
            log.warning(
                "AXES: Locking out %s after repeated login failures.", client_str
            )

            request.axes_locked_out = True
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )

        # 5. database entry: Log for ever the attempt in the AccessFailureLog
        if settings.AXES_ENABLE_ACCESS_FAILURE_LOG:
            with transaction.atomic(using=router.db_for_write(AccessFailureLog)):
                AccessFailureLog.objects.create(
                    username=username,
                    ip_address=request.axes_ip_address,
                    user_agent=request.axes_user_agent,
                    http_accept=request.axes_http_accept,
                    path_info=request.axes_path_info,
                    attempt_time=request.axes_attempt_time,
                    locked_out=request.axes_locked_out,
                )
                self.remove_out_of_limit_failure_logs(username=username)

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        When user logs in, update the AccessLog related to the user.
        """

        # 1. database query: Clean up expired user attempts from the database
        clean_expired_user_attempts(request.axes_attempt_time)

        username = user.get_username()
        credentials = get_credentials(username)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful login by %s.", client_str)

        if not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Insert new access logs with login time
            AccessLog.objects.create(
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                attempt_time=request.axes_attempt_time,
                # evaluate session hash here to ensure having the correct
                # value which is stored on the backend
                session_hash=get_client_session_hash(request),
            )

        if settings.AXES_RESET_ON_SUCCESS:
            # 3. database query: Reset failed attempts for the logging in user
            count = reset_user_attempts(request, credentials)
            log.info(
                "AXES: Deleted %d failed login attempts by %s from database.",
                count,
                client_str,
            )

    def user_logged_out(self, sender, request, user, **kwargs):
        """
        When user logs out, update the AccessLog related to the user.
        """

        # 1. database query: Clean up expired user attempts from the database
        clean_expired_user_attempts(request.axes_attempt_time)

        username = user.get_username() if user else None
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful logout by %s.", client_str)

        if username and not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Update existing attempt logs with logout time
            AccessLog.objects.filter(
                username=username,
                logout_time__isnull=True,
                # update only access log for given session
                session_hash=get_client_session_hash(request),
            ).update(logout_time=request.axes_attempt_time)

    def post_save_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post save signal.

        When needed, all post_save actions for this backend should be located
        here.
        """

    def post_delete_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post delete signal.

        When needed, all post_delete actions for this backend should be located
        here.
        """
