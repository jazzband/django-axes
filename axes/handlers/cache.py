from logging import getLogger

from axes.conf import settings
from axes.exceptions import AxesSignalPermissionDenied
from axes.handlers.base import AxesBaseHandler
from axes.signals import user_locked_out
from axes.helpers import (
    get_cache,
    get_cache_timeout,
    get_client_cache_key,
    get_client_ip_address,
    get_client_path_info,
    get_client_str,
    get_client_username,
    get_client_user_agent,
    get_credentials,
)

log = getLogger(settings.AXES_LOGGER)


class AxesCacheHandler(AxesBaseHandler):  # pylint: disable=too-many-locals
    """
    Signal handler implementation that records user login attempts to cache and locks users out if necessary.
    """

    def __init__(self):
        self.cache = get_cache()
        self.cache_timeout = get_cache_timeout()

    def get_failures(self, request, credentials=None, attempt_time=None) -> int:
        cache_key = get_client_cache_key(request, credentials)
        return self.cache.get(cache_key, default=0)

    def user_login_failed(self, sender, credentials, request=None, **kwargs):  # pylint: disable=too-many-locals
        """
        When user login fails, save attempt record in cache and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should be locked out.
        """

        if request is None:
            log.error('AXES: AxesCacheHandler.user_login_failed does not function without a request.')
            return

        username = get_client_username(request, credentials)
        ip_address = get_client_ip_address(request)
        user_agent = get_client_user_agent(request)
        path_info = get_client_path_info(request)
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        if self.is_whitelisted(request, credentials):
            log.info('AXES: Login failed from whitelisted client %s.', client_str)
            return

        failures_since_start = 1 + self.get_failures(request, credentials)

        if failures_since_start > 1:
            log.warning(
                'AXES: Repeated login failure by %s. Count = %d of %d. Updating existing record in the cache.',
                client_str,
                failures_since_start,
                settings.AXES_FAILURE_LIMIT,
            )
        else:
            log.warning(
                'AXES: New login failure by %s. Creating new record in the cache.',
                client_str,
            )

        cache_key = get_client_cache_key(request, credentials)
        self.cache.set(cache_key, failures_since_start, self.cache_timeout)

        if failures_since_start >= settings.AXES_FAILURE_LIMIT:
            log.warning('AXES: Locking out %s after repeated login failures.', client_str)

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
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        log.info('AXES: Successful login by %s.', client_str)

        if settings.AXES_RESET_ON_SUCCESS:
            cache_key = get_client_cache_key(request, credentials)
            failures_since_start = self.cache.get(cache_key, default=0)
            self.cache.delete(cache_key)
            log.info('AXES: Deleted %d failed login attempts by %s from cache.', failures_since_start, client_str)

    def user_logged_out(self, sender, request, user, **kwargs):
        username = user.get_username()
        ip_address = get_client_ip_address(request)
        user_agent = get_client_user_agent(request)
        path_info = get_client_path_info(request)
        client_str = get_client_str(username, ip_address, user_agent, path_info)

        log.info('AXES: Successful logout by %s.', client_str)
