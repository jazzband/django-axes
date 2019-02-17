from typing import Any, Dict, Optional

from django.http import HttpRequest


class AxesBaseHandler:  # pylint: disable=unused-argument
    """
    Handler API definition for subclassing handlers that can be used with the AxesProxyHandler.

    If you wish to implement your own handler class just override the methods you wish to specialize
    and define the class to be used with ``settings.AXES_HANDLER = 'dotted.full.path.to.YourClass'``.
    """

    def is_allowed_to_authenticate(
            self,
            request: HttpRequest,
            credentials: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Check if the user is allowed to authenticate into the site.
        """

        raise NotImplementedError('The Axes handler class needs a method definition for is_allowed_to_authenticate')

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
