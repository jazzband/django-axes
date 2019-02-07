from django.core.exceptions import PermissionDenied


class AxesPermissionDenied(PermissionDenied):
    """
    Base class for permission denied errors raised by axes specifically for easier debugging.

    Two different types of errors are used because of the behaviour Django has:

    - If an authentication backend raises a PermissionDenied error the authentication flow is aborted.
    - If another component raises a PermissionDenied error a HTTP 403 Forbidden response is returned.
    """

    pass


class AxesSignalPermissionDenied(AxesPermissionDenied):
    """
    Raised by signal handler on failed authentication attempts to send user a HTTP 403 Forbidden status code.
    """

    pass


class AxesBackendPermissionDenied(AxesPermissionDenied):
    """
    Raised by authentication backend on locked out requests to stop the Django authentication flow.
    """

    pass


class AxesBackendRequestParameterRequired(ValueError):
    """
    Raised by authentication backend on invalid or missing request parameter value.
    """

    pass
