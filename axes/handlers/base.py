import re
from abc import ABC, abstractmethod
from typing import Optional
from warnings import warn

from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from axes.conf import settings
from axes.helpers import (
    get_failure_limit,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
    is_user_attempt_whitelisted,
)


class AbstractAxesHandler(ABC):
    """
    Contract that all handlers need to follow
    """

    @abstractmethod
    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_login_failed`` authentication signal.
        """
        raise NotImplementedError("user_login_failed should be implemented")

    @abstractmethod
    def user_logged_in(self, sender, request, user, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_logged_in`` authentication signal.
        """
        raise NotImplementedError("user_logged_in should be implemented")

    @abstractmethod
    def user_logged_out(self, sender, request, user, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_logged_out`` authentication signal.
        """
        raise NotImplementedError("user_logged_out should be implemented")

    @abstractmethod
    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        """
        Checks the number of failures associated to the given request and credentials.

        This is a virtual method that needs an implementation in the handler subclass
        if the ``settings.AXES_LOCK_OUT_AT_FAILURE`` flag is set to ``True``.
        """
        raise NotImplementedError("get_failures should be implemented")


class AxesBaseHandler:  # pylint: disable=unused-argument
    """
    Handler API definition for implementations that are used by the ``AxesProxyHandler``.

    If you wish to specialize your own handler class, override the necessary methods
    and configure the class for use by setting ``settings.AXES_HANDLER = 'module.path.to.YourClass'``.
    Make sure that new the handler is compliant with AbstractAxesHandler and make sure it extends from this mixin.
    Refer to `AxesHandler` for an example.

    The default implementation that is actually used by Axes is ``axes.handlers.database.AxesDatabaseHandler``.

    .. note:: This is a virtual class and **can not be used without specialization**.
    """

    def is_allowed(self, request, credentials: Optional[dict] = None) -> bool:
        """
        Checks if the user is allowed to access or use given functionality such as a login view or authentication.

        This method is abstract and other backends can specialize it as needed, but the default implementation
        checks if the user has attempted to authenticate into the site too many times through the
        Django authentication backends and returns ``False`` if user exceeds the configured Axes thresholds.

        This checker can implement arbitrary checks such as IP whitelisting or blacklisting,
        request frequency checking, failed attempt monitoring or similar functions.

        Please refer to the ``axes.handlers.database.AxesDatabaseHandler`` for the default implementation
        and inspiration on some common checks and access restrictions before writing your own implementation.
        """

        if settings.AXES_ONLY_ADMIN_SITE and not self.is_admin_request(request):
            return True

        if self.is_blacklisted(request, credentials):
            return False

        if self.is_whitelisted(request, credentials):
            return True

        if self.is_locked(request, credentials):
            return False

        return True

    def is_blacklisted(self, request, credentials: Optional[dict] = None) -> bool:
        """
        Checks if the request or given credentials are blacklisted from access.
        """

        if is_client_ip_address_blacklisted(request):
            return True

        return False

    def is_whitelisted(self, request, credentials: Optional[dict] = None) -> bool:
        """
        Checks if the request or given credentials are whitelisted for access.
        """

        if is_user_attempt_whitelisted(request, credentials):
            return True

        if is_client_ip_address_whitelisted(request):
            return True

        if is_client_method_whitelisted(request):
            return True

        return False

    def is_locked(self, request, credentials: Optional[dict] = None) -> bool:
        """
        Checks if the request or given credentials are locked.
        """

        if settings.AXES_LOCK_OUT_AT_FAILURE:
            # get_failures will have to be implemented by each specialized handler
            return self.get_failures(  # type: ignore
                request, credentials
            ) >= get_failure_limit(request, credentials)

        return False

    def get_admin_url(self) -> Optional[str]:
        """
        Returns admin url if exists, otherwise returns None
        """
        try:
            return reverse("admin:index")
        except NoReverseMatch:
            return None

    def is_admin_request(self, request) -> bool:
        """
        Checks that request located under admin site
        """
        if hasattr(request, "path"):
            admin_url = self.get_admin_url()
            return (
                admin_url is not None
                and re.match(f"^{admin_url}", request.path) is not None
            )

        return False

    def is_admin_site(self, request) -> bool:
        """
        Checks if the request is NOT for admin site
        if `settings.AXES_ONLY_ADMIN_SITE` is True.
        """
        warn(
            (
                "This method is deprecated and will be removed in future versions. "
                "If you looking for method that checks if `request.path` located under "
                "admin site, use `is_admin_request` instead."
            ),
            DeprecationWarning,
        )
        if settings.AXES_ONLY_ADMIN_SITE and hasattr(request, "path"):
            try:
                admin_url = reverse("admin:index")
            except NoReverseMatch:
                return True
            return not re.match(f"^{admin_url}", request.path)

        return False

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        """
        Resets access attempts that match the given IP address or username.

        This method makes more sense for the DB backend, but as it is used by the ProxyHandler
        (via inherent), it needs to be defined here, so we get compliant with all proxy methods.

        Please overwrite it on each specialized handler as needed.
        """
        return 0

    def reset_logs(self, *, age_days: Optional[int] = None) -> int:
        """
        Resets access logs that are older than given number of days.

        This method makes more sense for the DB backend, but as it is used by the ProxyHandler
        (via inherent), it needs to be defined here, so we get compliant with all proxy methods.

        Please overwrite it on each specialized handler as needed.
        """
        return 0

    def reset_failure_logs(self, *, age_days: Optional[int] = None) -> int:
        """
        Resets access failure logs that are older than given number of days.

        This method makes more sense for the DB backend, but as it is used by the ProxyHandler
        (via inherent), it needs to be defined here, so we get compliant with all proxy methods.

        Please overwrite it on each specialized handler as needed.
        """
        return 0

    def remove_out_of_limit_failure_logs(
        self, *, username: str, limit: Optional[int] = None
    ) -> int:
        """Remove access failure logs that are over
        AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT for user username.

        This method makes more sense for the DB backend, but as it is used by the ProxyHandler
        (via inherent), it needs to be defined here, so we get compliant with all proxy methods.

        Please overwrite it on each specialized handler as needed.

        """
        return 0


class AxesHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal bare handler implementation without any storage backend.
    """

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        pass

    def user_logged_in(self, sender, request, user, **kwargs):
        pass

    def user_logged_out(self, sender, request, user, **kwargs):
        pass

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        return 0
