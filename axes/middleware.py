from axes.exceptions import AxesSignalPermissionDenied
from axes.utils import get_lockout_response


class AxesMiddleware:
    """
    Middleware that maps lockout signals into readable HTTP 403 Forbidden responses.

    Without this middleware the backend returns HTTP 403 errors with the
    django.views.defaults.permission_denied view that renders the 403.html
    template from the root template directory if found.

    Refer to the Django documentation for further information:

    https://docs.djangoproject.com/en/dev/ref/views/#the-403-http-forbidden-view

    To customize the error rendering, you can for example inherit this middleware
    and change the process_exception handler to your own liking.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):  # pylint: disable=inconsistent-return-statements
        """
        Exception handler that processes exceptions raised by the axes signal handler when request fails with login.

        Refer to axes.signals.log_user_login_failed for the error code.

        :param request: HTTPRequest that will be locked out.
        :param exception: Exception raised by Django views or signals. Only AxesSignalPermissionDenied will be handled.
        :return: HTTPResponse that indicates the lockout or None.
        """

        if isinstance(exception, AxesSignalPermissionDenied):
            return get_lockout_response(request)
