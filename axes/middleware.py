from typing import Callable

from axes.helpers import get_lockout_response


class AxesMiddleware:
    """
    Middleware that calculates necessary HTTP request attributes for attempt monitoring
    and maps lockout signals into readable HTTP 403 Forbidden responses.

    By default Django server returns ``PermissionDenied`` exceptions as HTTP 403 errors
    with the ``django.views.defaults.permission_denied`` view that renders
    the ``403.html`` template from the root template directory if found.

    This middleware recognizes the specialized attempt monitoring and lockout exceptions
    and uses the ``axes.helpers.get_lockout_response`` handler for returning
    customizable and context aware lockout message to the end user.

    To customize the error handling behaviour further, you can subclass this middleware
    and change the ``process_exception`` handler to your own liking.

    Please see the following configuration flags before customizing this handler:

    - ``AXES_LOCKOUT_TEMPLATE``,
    - ``AXES_LOCKOUT_URL``,
    - ``AXES_COOLOFF_MESSAGE``, and
    - ``AXES_PERMALOCK_MESSAGE``.
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if getattr(request, 'axes_locked_out', None):
            response = get_lockout_response(request)  # type: ignore

        return response
