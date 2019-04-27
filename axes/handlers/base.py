from axes.conf import settings
from axes.helpers import (
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
)
from axes.request import AxesHttpRequest


class AxesHandler:  # pylint: disable=unused-argument
    """
    Handler API definition for subclassing handlers that can be used with the AxesProxyHandler.

    Public API methods for this class are:

    - is_allowed
    - user_login_failed
    - user_logged_in
    - user_logged_out
    - post_save_access_attempt
    - post_delete_access_attempt

    Other API methods are considered internal and do not have fixed signatures.

    If you wish to implement your own handler class just override the methods you wish to specialize
    and define the class to be used with ``settings.AXES_HANDLER = 'dotted.full.path.to.YourClass'``.
    """

    def is_allowed(self, request: AxesHttpRequest, credentials: dict = None) -> bool:
        """
        Check if the user is allowed to access or use given functionality such as a login view or authentication.

        This method is abstract and other backends can specialize it as needed, but the default implementation
        checks if the user has attempted to authenticate into the site too many times through the
        Django authentication backends and returns false if user exceeds the configured Axes thresholds.

        This checker can implement arbitrary checks such as IP whitelisting or blacklisting,
        request frequency checking, failed attempt monitoring or similar functions.

        Please refer to the ``axes.handlers.database.AxesDatabaseHandler`` for the default implementation
        and inspiration on some common checks and access restrictions before writing your own implementation.
        """

        if self.is_blacklisted(request, credentials):
            return False

        if self.is_whitelisted(request, credentials):
            return True

        if self.is_locked(request, credentials):
            return False

        return True

    def user_login_failed(self, sender, credentials: dict, request: AxesHttpRequest = None, **kwargs):
        """
        Handle the Django user_login_failed authentication signal.
        """

    def user_logged_in(self, sender, request: AxesHttpRequest, user, **kwargs):
        """
        Handle the Django user_logged_in authentication signal.
        """

    def user_logged_out(self, sender, request: AxesHttpRequest, user, **kwargs):
        """
        Handle the Django user_logged_out authentication signal.
        """

    def post_save_access_attempt(self, instance, **kwargs):
        """
        Handle the Axes AccessAttempt object post save signal.
        """

    def post_delete_access_attempt(self, instance, **kwargs):
        """
        Handle the Axes AccessAttempt object post delete signal.
        """

    def is_blacklisted(self, request: AxesHttpRequest, credentials: dict = None) -> bool:  # pylint: disable=unused-argument
        """
        Check if the request or given credentials are blacklisted from access.
        """

        if is_client_ip_address_blacklisted(request):
            return True

        return False

    def is_whitelisted(self, request: AxesHttpRequest, credentials: dict = None) -> bool:  # pylint: disable=unused-argument
        """
        Check if the request or given credentials are whitelisted for access.
        """

        if is_client_ip_address_whitelisted(request):
            return True

        if is_client_method_whitelisted(request):
            return True

        return False

    def is_locked(self, request: AxesHttpRequest, credentials: dict = None) -> bool:
        """
        Check if the request or given credentials are locked.
        """

        if settings.AXES_LOCK_OUT_AT_FAILURE:
            return self.get_failures(request, credentials) >= settings.AXES_FAILURE_LIMIT

        return False

    def get_failures(self, request: AxesHttpRequest, credentials: dict = None) -> int:
        """
        Check the number of failures associated to the given request and credentials.
        """

        raise NotImplementedError('The Axes handler class needs a method definition for get_failures')
