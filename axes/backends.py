from django.contrib.auth.backends import ModelBackend

from axes.exceptions import AxesBackendPermissionDenied, AxesBackendRequestParameterRequired
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_credentials, get_lockout_message
from axes.request import AxesHttpRequest


class AxesBackend(ModelBackend):
    """
    Authentication backend class that forbids login attempts for locked out users.

    Use this class as the first item of ``AUTHENTICATION_BACKENDS`` to
    prevent locked out users from being logged in by the Django authentication flow.

    **Note:** this backend does not log your user in and delegates login to the
    backends that are configured after it in the ``AUTHENTICATION_BACKENDS`` list.
    """

    def authenticate(self, request: AxesHttpRequest, username: str = None, password: str = None, **kwargs: dict):
        """
        Checks user lockout status and raise a PermissionDenied if user is not allowed to log in.

        This method interrupts the login flow and inserts  error message directly to the
        ``response_context`` attribute that is supplied as a keyword argument.

        :keyword response_context: kwarg that will be have its ``error`` attribute updated with context.
        :raises AxesBackendRequestParameterRequired: if request parameter is not passed.
        :raises AxesBackendPermissionDenied: if user is already locked out.
        """

        if request is None:
            raise AxesBackendRequestParameterRequired('AxesBackend requires a request as an argument to authenticate')

        credentials = get_credentials(username=username, password=password, **kwargs)

        if AxesProxyHandler.is_allowed(request, credentials):
            return

        # Locked out, don't try to authenticate, just update response_context and return.
        # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.

        error_msg = get_lockout_message()
        response_context = kwargs.get('response_context', {})
        response_context['error'] = error_msg

        # Raise an error that stops the authentication flows at django.contrib.auth.authenticate.
        # This error stops bubbling up at the authenticate call which catches backend PermissionDenied errors.
        # After this error is caught by authenticate it emits a signal indicating user login failed,
        # which is processed by axes.signals.log_user_login_failed which logs the attempt and raises
        # a second exception which bubbles up the middleware stack and produces a HTTP 403 Forbidden reply
        # in the axes.middleware.AxesMiddleware.process_exception middleware exception handler.

        raise AxesBackendPermissionDenied('AxesBackend detected that the given user is locked out')
