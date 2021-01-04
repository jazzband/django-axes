from typing import Callable

from django.conf import settings

from axes.helpers import get_lockout_response


class AxesMiddleware:
    """
    Middleware that calculates necessary HTTP request attributes for attempt monitoring
    and maps lockout signals into readable HTTP 403 Forbidden responses.

    If a project uses ``django rest framework`` then the middleware updates the
    request and checks whether the limit has been exceeded. It's needed only
    for integration with DRF because it uses its own request object.

    This middleware recognizes a logout monitoring flag in the request and
    and uses the ``axes.helpers.get_lockout_response`` handler for returning
    customizable and context aware lockout message to the end user if necessary.

    To customize the lockout handling behaviour further, you can subclass this middleware
    and change the ``__call__`` method to your own liking.

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

        if settings.AXES_ENABLED:
            if getattr(request, "axes_locked_out", None):
                response = get_lockout_response(request)  # type: ignore

        return response
