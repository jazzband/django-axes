from logging import getLogger

from django.db.models import Max
from django.utils.timezone import now

from axes.attempts import get_cache_key, is_already_locked
from axes.attempts import get_cache_timeout
from axes.attempts import get_user_attempts
from axes.attempts import ip_in_whitelist
from axes.attempts import reset_user_attempts
from axes.conf import settings
from axes.exceptions import AxesSignalPermissionDenied
from axes.models import AccessLog, AccessAttempt
from axes.signals import user_locked_out
from axes.utils import get_client_str, get_client_user_agent
from axes.utils import query2str
from axes.utils import get_axes_cache, get_client_ip, get_client_username, get_credentials


log = getLogger(settings.AXES_LOGGER)


class AxesHandler:  # pylint: disable=too-many-locals
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.
    """

    def user_login_failed(self, sender, credentials, request, **kwargs):  # pylint: disable=unused-argument
        """
        When user login fails, save AccessAttempt record in database and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should is locked out
        """

        if request is None:
            log.warning('AxesHandler.user_login_failed does not function without a request.')
            return

        username = get_client_username(request, credentials)
        ip_address = get_client_ip(request)
        user_agent = get_client_user_agent(request)
        path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
        http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        if settings.AXES_NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip_address):
            log.info('Login failed from whitelisted IP %s.', ip_address)
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
                    query2str(request.GET),
                )
                attempt.post_data = template.format(
                    attempt.post_data,
                    query2str(request.POST)
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
            # used in counting failures is handled elsewhere, so we just record # everything here.
            AccessAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,

                get_data=query2str(request.GET),
                post_data=query2str(request.POST),
                http_accept=http_accept,
                path_info=path_info,
                failures_since_start=failures,
            )

            log.info(
                'AXES: New login failure by %s. Creating access record.',
                client_str,
            )

        if is_already_locked(request, credentials):
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
        ip_address = get_client_ip(request)
        user_agent = get_client_user_agent(request)
        path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
        http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
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

        log.info('AXES: Successful logout by %s.', user)

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
