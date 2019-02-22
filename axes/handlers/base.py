from typing import Any, Dict, Optional

from django.http import HttpRequest


class AxesBaseHandler:  # pylint: disable=unused-argument
    """
    Handler API definition for subclassing handlers that can be used with the AxesProxyHandler.

    If you wish to implement your own handler class just override the methods you wish to specialize
    and define the class to be used with ``settings.AXES_HANDLER = 'dotted.full.path.to.YourClass'``.
    """

    def is_allowed(self, request: HttpRequest, credentials: Optional[Dict[str, Any]] = None) -> bool:
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

        raise NotImplementedError('The Axes handler class needs a method definition for is_allowed')

    def user_login_failed(self, sender, credentials: Dict[str, Any], request: HttpRequest, **kwargs):
        """
        Handle the Django user_login_failed authentication signal.
        """

    def user_logged_in(self, sender, request: HttpRequest, user, **kwargs):
        """
        Handle the Django user_logged_in authentication signal.
        """

    def user_logged_out(self, sender, request: HttpRequest, user, **kwargs):
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
