from logging import getLogger
from typing import Optional

from axes.conf import settings
from axes.handlers.base import AxesBaseHandler, AbstractAxesHandler
from axes.helpers import (
    get_cache,
    get_cache_timeout,
    get_client_cache_keys,
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_lockout_parameters,
)
from axes.models import AccessAttempt
from axes.signals import user_locked_out

log = getLogger(__name__)


class AxesCacheHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that records user login attempts to cache and locks users out if necessary.
    """

    def __init__(self):
        self.cache = get_cache()

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        cache_keys: list = []
        count = 0

        if ip_address is None and username is None:
            raise NotImplementedError("Cannot clear all entries from cache")
        if ip_or_username:
            raise NotImplementedError(
                "Due to the cache key ip_or_username=True is not supported"
            )

        cache_keys.extend(
            get_client_cache_keys(
                AccessAttempt(username=username, ip_address=ip_address)
            )
        )

        for cache_key in cache_keys:
            deleted = self.cache.delete(cache_key)
            count += int(deleted) if deleted is not None else 1

        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        cache_keys = get_client_cache_keys(request, credentials)
        failure_count = max(
            self.cache.get(cache_key, default=0) for cache_key in cache_keys
        )
        return failure_count

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        When user login fails, save attempt record in cache and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should be locked out.
        """

        if request is None:
            log.error(
                "AXES: AxesCacheHandler.user_login_failed does not function without a request."
            )
            return

        username = get_client_username(request, credentials)
        lockout_parameters = get_lockout_parameters(request, credentials)
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
            return

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

        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        if self.is_whitelisted(request, credentials):
            log.info("AXES: Login failed from whitelisted client %s.", client_str)
            return

        cache_keys = get_client_cache_keys(request, credentials)
        cache_timeout = get_cache_timeout()
        failures = []
        for cache_key in cache_keys:
            added = self.cache.add(key=cache_key, value=1, timeout=cache_timeout)
            if added:
                failures.append(1)
            else:
                failures.append(self.cache.incr(key=cache_key, delta=1))
                self.cache.touch(key=cache_key, timeout=cache_timeout)

        failures_since_start = max(failures)
        request.axes_failures_since_start = failures_since_start

        if failures_since_start > 1:
            log.warning(
                "AXES: Repeated login failure by %s. Count = %d of %d. Updating existing record in the cache.",
                client_str,
                failures_since_start,
                get_failure_limit(request, credentials),
            )
        else:
            log.warning(
                "AXES: New login failure by %s. Creating new record in the cache.",
                client_str,
            )

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

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        When user logs in, update the AccessLog related to the user.
        """

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

        if settings.AXES_RESET_ON_SUCCESS:
            cache_keys = get_client_cache_keys(request, credentials)
            for cache_key in cache_keys:
                failures_since_start = self.cache.get(cache_key, default=0)
                self.cache.delete(cache_key)
                log.info(
                    "AXES: Deleted %d failed login attempts by %s from cache.",
                    failures_since_start,
                    client_str,
                )

    def user_logged_out(self, sender, request, user, **kwargs):
        username = user.get_username() if user else None
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful logout by %s.", client_str)
