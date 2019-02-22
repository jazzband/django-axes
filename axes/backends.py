from django.contrib.auth.backends import ModelBackend

from axes.exceptions import AxesBackendPermissionDenied, AxesBackendRequestParameterRequired
from axes.handlers.proxy import AxesProxyHandler
from axes.utils import get_credentials, get_lockout_message


class AxesBackend(ModelBackend):
    """
    Authentication backend that forbids login attempts for locked out users.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Check user lock out status and raises PermissionDenied if user is not allowed to log in.

        Inserts errors directly to `return_context` that is supplied as a keyword argument.

        Use this on top of your AUTHENTICATION_BACKENDS list to prevent locked out users
        from being authenticated in the standard Django authentication flow.

        Note that this method does not log your user in and delegates login to other backends.

        :param request: see django.contrib.auth.backends.ModelBackend.authenticate
        :param username: see django.contrib.auth.backends.ModelBackend.authenticate
        :param password: see django.contrib.auth.backends.ModelBackend.authenticate
        :param kwargs: see django.contrib.auth.backends.ModelBackend.authenticate
        :keyword response_context: context dict that will be updated with error information
        :raises AxesBackendRequestParameterRequired: if request parameter is not given correctly
        :raises AxesBackendPermissionDenied: if user is already locked out
        :return: None
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
