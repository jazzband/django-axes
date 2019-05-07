from typing import Callable

from django.http import HttpRequest
from django.utils.timezone import now

from axes.exceptions import AxesSignalPermissionDenied
from axes.helpers import (
    get_client_ip_address,
    get_client_user_agent,
    get_client_path_info,
    get_client_http_accept,
    get_lockout_response,
    toggleable,
)
from axes.request import AxesHttpRequest


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

    def __call__(self, request: HttpRequest):
        self.update_request(request)
        return self.get_response(request)

    @toggleable
    def update_request(self, request: HttpRequest):
        """
        Construct an ``AxesHttpRequest`` from the given ``HttpRequest``
        by updating the request with necessary attempt tracking attributes.

        This method is called by the middleware class ``__call__`` method
        when iterating over the middleware stack.
        """

        request.axes_attempt_time = now()
        request.axes_ip_address = get_client_ip_address(request)
        request.axes_user_agent = get_client_user_agent(request)
        request.axes_path_info = get_client_path_info(request)
        request.axes_http_accept = get_client_http_accept(request)

    @toggleable
    def process_exception(self, request: AxesHttpRequest, exception):  # pylint: disable=inconsistent-return-statements
        """
        Handle exceptions raised by the Axes signal handler class when requests fail checks.

        Note that only ``AxesSignalPermissionDenied`` is handled by this middleware class.

        :return: Configured ``HttpResponse`` for failed authentication attempts and lockouts.
        """

        if isinstance(exception, AxesSignalPermissionDenied):
            return get_lockout_response(request)
