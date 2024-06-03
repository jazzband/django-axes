from typing import Optional
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest

from axes.exceptions import (
    AxesBackendPermissionDenied,
    AxesBackendRequestParameterRequired,
)
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_credentials, get_lockout_message, toggleable


class AxesStandaloneBackend:
    """
    Authentication backend class that forbids login attempts for locked out users.

    Use this class as the first item of ``AUTHENTICATION_BACKENDS`` to
    prevent locked out users from being logged in by the Django authentication flow.

    .. note:: This backend does not log your user in. It monitors login attempts.
              It also does not run any permissions checks at all.
              Authentication is handled by the following backends that are configured in ``AUTHENTICATION_BACKENDS``.
    """

    @toggleable
    def authenticate(
        self,
        request: HttpRequest,
        username: Optional[str] = None,
        password: Optional[str] = None,
        **kwargs: dict,
    ):
        """
        Checks user lockout status and raises an exception if user is not allowed to log in.

        This method interrupts the login flow and inserts  error message directly to the
        ``response_context`` attribute that is supplied as a keyword argument.

        :keyword response_context: kwarg that will be have its ``error`` attribute updated with context.
        :raises AxesBackendRequestParameterRequired: if request parameter is not passed.
        :raises AxesBackendPermissionDenied: if user is already locked out.
        """

        if request is None:
            raise AxesBackendRequestParameterRequired(
                "AxesBackend requires a request as an argument to authenticate"
            )

        credentials = get_credentials(username=username, password=password, **kwargs)

        if AxesProxyHandler.is_allowed(request, credentials):
            return

        # Locked out, don't try to authenticate, just update response_context and return.
        # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.

        error_msg = get_lockout_message()
        response_context = kwargs.get("response_context", {})
        response_context["error"] = error_msg

        # This flag can be used later to check if it was Axes that denied the login attempt.
        if not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT:
            request.axes_locked_out = True

        # Raise an error that stops the authentication flows at django.contrib.auth.authenticate.
        # This error stops bubbling up at the authenticate call which catches backend PermissionDenied errors.
        # After this error is caught by authenticate it emits a signal indicating user login failed,
        # which is processed by axes.signals.log_user_login_failed which logs and flags the failed request.
        # The axes.middleware.AxesMiddleware further processes the flagged request into a readable response.

        raise AxesBackendPermissionDenied(
            "AxesBackend detected that the given user is locked out"
        )


class AxesBackend(AxesStandaloneBackend, ModelBackend):
    """
    Axes authentication backend that also inherits from ModelBackend,
    and thus also performs other functions of ModelBackend such as permissions checks.

    Use this class as the first item of ``AUTHENTICATION_BACKENDS`` to
    prevent locked out users from being logged in by the Django authentication flow.

    .. note:: This backend does not log your user in. It monitors login attempts.
              Authentication is handled by the following backends that are configured in ``AUTHENTICATION_BACKENDS``.
    """
