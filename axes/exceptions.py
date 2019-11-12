from django.core.exceptions import PermissionDenied


class AxesBackendPermissionDenied(PermissionDenied):
    """
    Raised by authentication backend on locked out requests to stop the Django authentication flow.
    """


class AxesBackendRequestParameterRequired(ValueError):
    """
    Raised by authentication backend on invalid or missing request parameter value.
    """
