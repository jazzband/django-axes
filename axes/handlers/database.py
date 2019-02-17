from logging import getLogger
from typing import Any, Dict, Optional

from django.db.models import Max
from django.http import HttpRequest
from django.utils.timezone import now

from axes.attempts import (
    get_cache_key,
    get_user_attempts,
    reset_user_attempts,
)
from axes.conf import settings
from axes.exceptions import AxesSignalPermissionDenied
from axes.models import AccessLog, AccessAttempt
from axes.signals import user_locked_out
from axes.handlers.base import AxesBaseHandler
from axes.utils import (
    get_axes_cache,
    get_cache_timeout,
    get_client_ip_address,
    get_client_path_info,
    get_client_http_accept,
    get_client_str,
    get_client_username,
    get_client_user_agent,
    get_credentials,
    get_query_str,
    is_ip_address_in_whitelist,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
    is_client_username_whitelisted,
)


log = getLogger(settings.AXES_LOGGER)


class AxesDatabaseHandler(AxesBaseHandler):  # pylint: disable=too-many-locals
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.
    """

    def is_allowed_to_authenticate(self, request: HttpRequest, credentials: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if the request or given credentials are already locked by Axes.

        This function is called from

        - function decorators defined in ``axes.decorators``,
        - authentication backends defined in ``axes.backends``, and
        - signal handlers defined in ``axes.handlers``.

        This function checks the following facts for a given request:

        1. Is the request IP address _blacklisted_? If it is, return ``False``.
        2. Is the request IP address _whitelisted_? If it is, return ``True``.
        4. Is the request HTTP method _whitelisted_? If it is, return ``True``.
        3. Is the request user _whitelisted_? If it is, return ``True``.
        5. Is failed authentication attempt always allowed to proceed? If it is, return ``True``.
        6. Is failed authentication attempt count over the attempt limit? If it is, return ``False``.

        Refer to the function source code for the exact implementation.
        """

        if is_client_ip_address_blacklisted(request):
            return False

        if is_client_ip_address_whitelisted(request):
            return True

        if is_client_method_whitelisted(request):
            return True

        if is_client_username_whitelisted(request, credentials):
            return True

        if not settings.AXES_LOCK_OUT_AT_FAILURE:
            return True

        # Check failure statistics against cache
        cache_hash_key = get_cache_key(request, credentials)
        num_failures_cached = get_axes_cache().get(cache_hash_key)

        # Do not hit the database if we have an answer in the cache
        if num_failures_cached is not None:
            return num_failures_cached < settings.AXES_FAILURE_LIMIT

        # Check failure statistics against database
        attempts = get_user_attempts(request, credentials)
        failures = attempts.filter(
            failures_since_start__gte=settings.AXES_FAILURE_LIMIT,
        )

        return not failures.exists()

    def user_login_failed(self, sender, credentials, request, **kwargs):  # pylint: disable=too-many-locals
        """
        When user login fails, save AccessAttempt record in database and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should is locked out
        """

        if request is None:
            log.warning('AXES: AxesDatabaseHandler.user_login_failed does not function without a request.')
            return

        username = get_client_username(request, credentials)
        ip_address = get_client_ip_address(request)
        user_agent = get_client_user_agent(request)
        path_info = get_client_path_info(request)
        http_accept = get_client_http_accept(request)
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        if settings.AXES_NEVER_LOCKOUT_WHITELIST and is_ip_address_in_whitelist(ip_address):
            log.info('AXES: Login failed from whitelisted IP %s.', ip_address)
            return

        attempts = get_user_attempts(request, credentials)
        cache_key = get_cache_key(request, credentials)
        num_failures_cached = get_axes_cache().get(cache_key)

        if num_failures_cached:
            failures = num_failures_cached
        elif attempts:
            failures = attempts.aggregate(
                Max('failures_since_start'),
            )['failures_since_start__max']
        else:
            failures = 0

        # add a failed attempt for this user
        failures += 1
        get_axes_cache().set(
            cache_key,
            failures,
            get_cache_timeout(),
        )

        if attempts:
            # Update existing attempt information but do not touch the username, ip_address, or user_agent fields,
            # because attackers can request the site with multiple different usernames, addresses, or programs.
            for attempt in attempts:
                template = '{}\n---------\n{}'

                attempt.get_data = template.format(
                    attempt.get_data,
                    get_query_str(request.GET),
                )
                attempt.post_data = template.format(
                    attempt.post_data,
                    get_query_str(request.POST)
                )
                attempt.http_accept = http_accept
                attempt.path_info = path_info
                attempt.failures_since_start = failures
                attempt.attempt_time = now()
                attempt.save()

                log.info(
                    'AXES: Repeated login failure by %s. Count = %d of %d',
                    client_str,
                    failures,
                    settings.AXES_FAILURE_LIMIT,
                )
        else:
            # Record failed attempt. Whether or not the IP address or user agent is
            # used in counting failures is handled elsewhere, so we just record everything here.
            AccessAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,

                get_data=get_query_str(request.GET),
                post_data=get_query_str(request.POST),
                http_accept=http_accept,
                path_info=path_info,
                failures_since_start=failures,
            )

            log.info(
                'AXES: New login failure by %s. Creating access record.',
                client_str,
            )

        if not self.is_allowed_to_authenticate(request, credentials):
            log.warning(
                'AXES: Locked out %s after repeated login failures.',
                client_str,
            )

            user_locked_out.send(
                'axes',
                request=request,
                username=username,
                ip_address=ip_address,
            )

            raise AxesSignalPermissionDenied('Locked out due to repeated login failures.')

    def user_logged_in(self, sender, request, user, **kwargs):  # pylint: disable=unused-argument
        """
        When user logs in, update the AccessLog related to the user.
        """

        username = user.get_username()
        credentials = get_credentials(username)
        ip_address = get_client_ip_address(request)
        user_agent = get_client_user_agent(request)
        path_info = get_client_path_info(request)
        http_accept = get_client_http_accept(request)
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        log.info(
            'AXES: Successful login by %s.',
            client_str,
        )

        if not settings.AXES_DISABLE_SUCCESS_ACCESS_LOG:
            AccessLog.objects.create(
                user_agent=user_agent,
                ip_address=ip_address,
                username=username,
                http_accept=http_accept,
                path_info=path_info,
                trusted=True,
            )

        if settings.AXES_RESET_ON_SUCCESS:
            count = reset_user_attempts(request, credentials)
            log.info(
                'AXES: Deleted %d failed login attempts by %s.',
                count,
                client_str,
            )

    def user_logged_out(self, sender, request, user, **kwargs):  # pylint: disable=unused-argument
        """
        When user logs out, update the AccessLog related to the user.
        """

        username = user.get_username()
        ip_address = get_client_ip_address(request)
        user_agent = get_client_user_agent(request)
        path_info = get_client_path_info(request)
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        log.info(
            'AXES: Successful logout by %s.',
            client_str,
        )

        if user and not settings.AXES_DISABLE_ACCESS_LOG:
            AccessLog.objects.filter(
                username=user.get_username(),
                logout_time__isnull=True,
            ).update(
                logout_time=now(),
            )

    def post_save_access_attempt(self, instance, **kwargs):  # pylint: disable=unused-argument
        """
        Update cache after saving AccessAttempts.
        """

        cache_key = get_cache_key(instance)

        if not get_axes_cache().get(cache_key):
            get_axes_cache().set(
                cache_key,
                instance.failures_since_start,
                get_cache_timeout(),
            )

    def post_delete_access_attempt(self, instance, **kwargs):  # pylint: disable=unused-argument
        """
        Update cache after deleting AccessAttempts.
        """

        cache_hash_key = get_cache_key(instance)
        get_axes_cache().delete(cache_hash_key)
