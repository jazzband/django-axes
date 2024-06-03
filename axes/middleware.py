from typing import Callable

from asgiref.sync import iscoroutinefunction, markcoroutinefunction, sync_to_async
from django.conf import settings
from django.http import HttpRequest, HttpResponse

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

    async_capable = True
    sync_capable = True

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Exit out to async mode, if needed
        if iscoroutinefunction(self):
            return self.__acall__(request)

        response = self.get_response(request)
        if settings.AXES_ENABLED:
            if getattr(request, "axes_locked_out", None):
                credentials = getattr(request, "axes_credentials", None)
                response = get_lockout_response(request, credentials)  # type: ignore

        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponse:
        response = await self.get_response(request)

        if settings.AXES_ENABLED:
            if getattr(request, "axes_locked_out", None):
                credentials = getattr(request, "axes_credentials", None)
                response = await sync_to_async(
                    get_lockout_response, thread_sensitive=True
                )(
                    request, credentials
                )  # type: ignore

        return response
