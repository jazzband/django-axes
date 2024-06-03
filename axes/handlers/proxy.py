# pylint: disable=arguments-differ
# pylint generates false negatives from proxy class method overrides

from logging import getLogger
from typing import Optional

from django.utils.module_loading import import_string
from django.utils.timezone import now

from axes.conf import settings
from axes.handlers.base import AxesBaseHandler, AbstractAxesHandler, AxesHandler
from axes.helpers import (
    get_client_ip_address,
    get_client_user_agent,
    get_client_path_info,
    get_client_http_accept,
    toggleable,
)

log = getLogger(__name__)


class AxesProxyHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Proxy interface for configurable Axes signal handler class.

    If you wish to implement a custom version of this handler,
    you can override the settings.AXES_HANDLER configuration string
    with a class that implements a compatible interface and methods.

    Defaults to using axes.handlers.proxy.AxesProxyHandler if not overridden.
    Refer to axes.handlers.proxy.AxesProxyHandler for default implementation.
    """

    implementation = None  # type: AxesHandler

    @classmethod
    def get_implementation(cls, force: bool = False) -> AxesHandler:
        """
        Fetch and initialize configured handler implementation and memoize it to avoid reinitialization.

        This method is re-entrant and can be called multiple times from e.g. Django application loader.
        """

        if force or not cls.implementation:
            cls.implementation = import_string(settings.AXES_HANDLER)()
        return cls.implementation

    @classmethod
    def reset_attempts(
        cls,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        return cls.get_implementation().reset_attempts(
            ip_address=ip_address, username=username, ip_or_username=ip_or_username
        )

    @classmethod
    def reset_logs(cls, *, age_days: Optional[int] = None) -> int:
        return cls.get_implementation().reset_logs(age_days=age_days)

    @classmethod
    def reset_failure_logs(cls, *, age_days: Optional[int] = None) -> int:
        return cls.get_implementation().reset_failure_logs(age_days=age_days)

    @classmethod
    def remove_out_of_limit_failure_logs(
        cls, *, username: str, limit: Optional[int] = None
    ) -> int:
        return cls.get_implementation().remove_out_of_limit_failure_logs(
            username=username
        )

    @staticmethod
    def update_request(request):
        """
        Update request attributes before passing them into the selected handler class.
        """

        if request is None:
            log.error(
                "AXES: AxesProxyHandler.update_request can not set request attributes to a None request"
            )
            return
        if not hasattr(request, "axes_updated"):
            if not hasattr(request, "axes_locked_out"):
                request.axes_locked_out = False
            request.axes_attempt_time = now()
            request.axes_ip_address = get_client_ip_address(request)
            request.axes_user_agent = get_client_user_agent(request)
            request.axes_path_info = get_client_path_info(request)
            request.axes_http_accept = get_client_http_accept(request)
            request.axes_failures_since_start = None
            request.axes_updated = True
            request.axes_credentials = None

    @classmethod
    def is_locked(cls, request, credentials: Optional[dict] = None) -> bool:
        cls.update_request(request)
        return cls.get_implementation().is_locked(request, credentials)

    @classmethod
    def is_allowed(cls, request, credentials: Optional[dict] = None) -> bool:
        cls.update_request(request)
        return cls.get_implementation().is_allowed(request, credentials)

    @classmethod
    def get_failures(cls, request, credentials: Optional[dict] = None) -> int:
        cls.update_request(request)
        return cls.get_implementation().get_failures(request, credentials)

    @classmethod
    @toggleable
    def user_login_failed(cls, sender, credentials: dict, request=None, **kwargs):
        cls.update_request(request)
        return cls.get_implementation().user_login_failed(
            sender, credentials, request, **kwargs
        )

    @classmethod
    @toggleable
    def user_logged_in(cls, sender, request, user, **kwargs):
        cls.update_request(request)
        return cls.get_implementation().user_logged_in(sender, request, user, **kwargs)

    @classmethod
    @toggleable
    def user_logged_out(cls, sender, request, user, **kwargs):
        cls.update_request(request)
        return cls.get_implementation().user_logged_out(sender, request, user, **kwargs)

    @classmethod
    @toggleable
    def post_save_access_attempt(cls, instance, **kwargs):
        return cls.get_implementation().post_save_access_attempt(instance, **kwargs)

    @classmethod
    @toggleable
    def post_delete_access_attempt(cls, instance, **kwargs):
        return cls.get_implementation().post_delete_access_attempt(instance, **kwargs)
