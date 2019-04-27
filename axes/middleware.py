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
)
from axes.request import AxesHttpRequest


class AxesMiddleware:
    """
    Middleware that maps lockout signals into readable HTTP 403 Forbidden responses.

    Without this middleware the backend returns HTTP 403 errors with the
    ``django.views.defaults.permission_denied`` view that renders the ``403.html``
    template from the root template directory if found.
    This middleware uses the ``axes.helpers.get_lockout_response`` handler
    for returning a context aware lockout message to the end user.

    To customize the error rendering, you can subclass this middleware
    and change the ``process_exception`` handler to your own liking.
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        self.update_request(request)
        return self.get_response(request)

    def update_request(self, request: HttpRequest):
        """
        Update given Django ``HttpRequest`` with necessary attributes
        before passing it on the ``get_response`` for further
        Django middleware and view processing.
        """

        request.axes_attempt_time = now()
        request.axes_ip_address = get_client_ip_address(request)
        request.axes_user_agent = get_client_user_agent(request)
        request.axes_path_info = get_client_path_info(request)
        request.axes_http_accept = get_client_http_accept(request)

    def process_exception(self, request: AxesHttpRequest, exception):  # pylint: disable=inconsistent-return-statements
        """
        Exception handler that processes exceptions raised by the Axes signal handler when request fails with login.

        Only ``axes.exceptions.AxesSignalPermissionDenied`` exception is handled by this middleware.
        """

        if isinstance(exception, AxesSignalPermissionDenied):
            return get_lockout_response(request)
