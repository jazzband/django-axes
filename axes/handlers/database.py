from logging import getLogger

from django.db.models import Max, Value
from django.db.models.functions import Concat

from axes.attempts import (
    clean_expired_user_attempts,
    get_user_attempts,
    is_user_attempt_whitelisted,
    reset_user_attempts,
)
from axes.conf import settings
from axes.handlers.base import AxesHandler
from axes.models import AccessLog, AccessAttempt
from axes.signals import user_locked_out
from axes.helpers import (
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_query_str,
)


log = getLogger(settings.AXES_LOGGER)


class AxesDatabaseHandler(AxesHandler):  # pylint: disable=too-many-locals
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.
    """

    def get_failures(self, request, credentials: dict = None) -> int:
        attempts = get_user_attempts(request, credentials)
        return attempts.aggregate(Max('failures_since_start'))['failures_since_start__max'] or 0

    def is_locked(self, request, credentials: dict = None):
        if is_user_attempt_whitelisted(request, credentials):
            return False

        return super().is_locked(request, credentials)

    def user_login_failed(
            self,
            sender,
            credentials: dict,
            request = None,
            **kwargs
    ):  # pylint: disable=too-many-locals
        """
        When user login fails, save AccessAttempt record in database and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should be locked out.
        """

        if request is None:
            log.error('AXES: AxesDatabaseHandler.user_login_failed does not function without a request.')
            return

        # 1. database query: Clean up expired user attempts from the database before logging new attempts
        clean_expired_user_attempts(request.axes_attempt_time)

        username = get_client_username(request, credentials)
        client_str = get_client_str(username, request.axes_ip_address, request.axes_user_agent, request.axes_path_info)

        get_data = get_query_str(request.GET)
        post_data = get_query_str(request.POST)

        if self.is_whitelisted(request, credentials):
            log.info('AXES: Login failed from whitelisted client %s.', client_str)
            return

        # 2. database query: Calculate the current maximum failure number from the existing attempts
        failures_since_start = 1 + self.get_failures(request, credentials)

        # 3. database query: Insert or update access records with the new failure data
        if failures_since_start > 1:
            # Update failed attempt information but do not touch the username, IP address, or user agent fields,
            # because attackers can request the site with multiple different configurations
            # in order to bypass the defense mechanisms that are used by the site.

            log.warning(
                'AXES: Repeated login failure by %s. Count = %d of %d. Updating existing record in the database.',
                client_str,
                failures_since_start,
                get_failure_limit(request, credentials),
            )

            separator = '\n---------\n'

            attempts = get_user_attempts(request, credentials)
            attempts.update(
                get_data=Concat('get_data', Value(separator + get_data)),
                post_data=Concat('post_data', Value(separator + post_data)),
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                failures_since_start=failures_since_start,
                attempt_time=request.axes_attempt_time,
            )
        else:
            # Record failed attempt with all the relevant information.
            # Filtering based on username, IP address and user agent handled elsewhere,
            # and this handler just records the available information for further use.

            log.warning(
                'AXES: New login failure by %s. Creating new record in the database.',
                client_str,
            )

            AccessAttempt.objects.create(
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                get_data=get_data,
                post_data=post_data,
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                failures_since_start=failures_since_start,
                attempt_time=request.axes_attempt_time,
            )

        if settings.AXES_LOCK_OUT_AT_FAILURE and failures_since_start >= get_failure_limit(request, credentials):
            log.warning('AXES: Locking out %s after repeated login failures.', client_str)

            request.axes_locked_out = True

            user_locked_out.send(
                'axes',
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )

    def user_logged_in(self, sender, request, user, **kwargs):  # pylint: disable=unused-argument
        """
        When user logs in, update the AccessLog related to the user.
        """

        # 1. database query: Clean up expired user attempts from the database
        clean_expired_user_attempts(request.axes_attempt_time)

        username = user.get_username()
        credentials = get_credentials(username)
        client_str = get_client_str(username, request.axes_ip_address, request.axes_user_agent, request.axes_path_info)

        log.info('AXES: Successful login by %s.', client_str)

        if not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Insert new access logs with login time
            AccessLog.objects.create(
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                attempt_time=request.axes_attempt_time,
            )

        if settings.AXES_RESET_ON_SUCCESS:
            # 3. database query: Reset failed attempts for the logging in user
            count = reset_user_attempts(request, credentials)
            log.info('AXES: Deleted %d failed login attempts by %s from database.', count, client_str)

    def user_logged_out(self, sender, request, user, **kwargs):  # pylint: disable=unused-argument
        """
        When user logs out, update the AccessLog related to the user.
        """

        # 1. database query: Clean up expired user attempts from the database
        clean_expired_user_attempts(request.axes_attempt_time)

        username = user.get_username() if user else None
        client_str = get_client_str(username, request.axes_ip_address, request.axes_user_agent, request.axes_path_info)

        log.info('AXES: Successful logout by %s.', client_str)

        if username and not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Update existing attempt logs with logout time
            AccessLog.objects.filter(
                username=username,
                logout_time__isnull=True,
            ).update(
                logout_time=request.axes_attempt_time,
            )
