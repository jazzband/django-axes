import re

from django.urls import reverse

from axes.conf import settings
from axes.helpers import (
    get_failure_limit,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
    is_user_attempt_whitelisted,
)


class AxesHandler:  # pylint: disable=unused-argument
    """
    Handler API definition for implementations that are used by the ``AxesProxyHandler``.

    If you wish to specialize your own handler class, override the necessary methods
    and configure the class for use by setting ``settings.AXES_HANDLER = 'module.path.to.YourClass'``.

    The default implementation that is actually used by Axes is ``axes.handlers.database.AxesDatabaseHandler``.

    .. note:: This is a virtual class and **can not be used without specialization**.
    """

    def reset_attempts(self, *, ip_address: str = None, username: str = None) -> int:
        """
        Resets access attempts that match the given IP address or username.

        :raises NotImplementedError: if the handler does not support resetting attempts.
        """

        raise NotImplementedError(
            "Reset for access attempts is not supported on this backend"
        )

    def reset_logs(self, *, age_days: int = None) -> int:
        """
        Resets access logs that are older than given number of days.

        :raises NotImplementedError: if the handler does not support resetting logs.
        """

        raise NotImplementedError(
            "Reset for access logs is not supported on this backend"
        )

    def is_allowed(self, request, credentials: dict = None) -> bool:
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

        if self.is_admin_site(request):
            return True

        if self.is_blacklisted(request, credentials):
            return False

        if self.is_whitelisted(request, credentials):
            return True

        if self.is_locked(request, credentials):
            return False

        return True

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_login_failed`` authentication signal.
        """

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_logged_in`` authentication signal.
        """

    def user_logged_out(self, sender, request, user, **kwargs):
        """
        Handles the Django ``django.contrib.auth.signals.user_logged_out`` authentication signal.
        """

    def post_save_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post save signal.
        """

    def post_delete_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post delete signal.
        """

    def is_blacklisted(
        self, request, credentials: dict = None
    ) -> bool:  # pylint: disable=unused-argument
        """
        Checks if the request or given credentials are blacklisted from access.
        """

        if is_client_ip_address_blacklisted(request):
            return True

        return False

    def is_whitelisted(
        self, request, credentials: dict = None
    ) -> bool:  # pylint: disable=unused-argument
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

    def is_locked(self, request, credentials: dict = None) -> bool:
        """
        Checks if the request or given credentials are locked.
        """

        if settings.AXES_LOCK_OUT_AT_FAILURE:
            return self.get_failures(request, credentials) >= get_failure_limit(
                request, credentials
            )

        return False

    def get_failures(self, request, credentials: dict = None) -> int:
        """
        Checks the number of failures associated to the given request and credentials.

        This is a virtual method that needs an implementation in the handler subclass
        if the ``settings.AXES_LOCK_OUT_AT_FAILURE`` flag is set to ``True``.
        """

        raise NotImplementedError(
            "The Axes handler class needs a method definition for get_failures"
        )

    def is_admin_site(self, request) -> bool:
        """
        Checks if the request is for admin site.
        """
        if (
            settings.AXES_ONLY_ADMIN_SITE
            and hasattr(request, "path")
            and not re.match("^%s" % reverse("admin:index"), request.path)
        ):
            return True

        return False
