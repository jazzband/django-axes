from logging import getLogger
from typing import Any, Dict, Optional

from django.http import HttpRequest
from django.utils.module_loading import import_string

from axes.conf import settings
from axes.handlers.base import AxesBaseHandler

log = getLogger(settings.AXES_LOGGER)


class AxesProxyHandler(AxesBaseHandler):
    """
    Proxy interface for configurable Axes signal handler class.

    If you wish to implement a custom version of this handler,
    you can override the settings.AXES_HANDLER configuration string
    with a class that implements a compatible interface and methods.

    Defaults to using axes.handlers.proxy.AxesProxyHandler if not overridden.
    Refer to axes.handlers.proxy.AxesProxyHandler for default implementation.
    """

    implementation = None  # type: AxesBaseHandler

    @classmethod
    def get_implementation(cls, force=False) -> AxesBaseHandler:
        """
        Fetch and initialize configured handler implementation and memoize it to avoid reinitialization.

        This method is re-entrant and can be called multiple times from e.g. Django application loader.
        """

        if force or not cls.implementation:
            cls.implementation = import_string(settings.AXES_HANDLER)()
        return cls.implementation

    @classmethod
    def is_allowed_to_authenticate(cls, request: HttpRequest, credentials: Optional[Dict[str, Any]] = None) -> bool:
        return cls.get_implementation().is_allowed_to_authenticate(request, credentials)

    @classmethod
    def user_login_failed(cls, sender: Any, credentials: Dict[str, Any], request: HttpRequest, **kwargs):
        return cls.get_implementation().user_login_failed(sender, credentials, request, **kwargs)

    @classmethod
    def user_logged_in(cls, sender: Any, request: HttpRequest, user, **kwargs):
        return cls.get_implementation().user_logged_in(sender, request, user, **kwargs)

    @classmethod
    def user_logged_out(cls, sender: Any, request: HttpRequest, user, **kwargs):
        return cls.get_implementation().user_logged_out(sender, request, user, **kwargs)

    @classmethod
    def post_save_access_attempt(cls, instance, **kwargs):
        return cls.get_implementation().post_save_access_attempt(instance, **kwargs)

    @classmethod
    def post_delete_access_attempt(cls, instance, **kwargs):
        return cls.get_implementation().post_delete_access_attempt(instance, **kwargs)
