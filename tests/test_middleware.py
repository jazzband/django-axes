from django.conf import settings
from django.http import HttpResponse, HttpRequest
from django.test import override_settings

from axes.middleware import AxesMiddleware
from tests.base import AxesTestCase


def get_username(request, credentials: dict) -> str:
    return credentials.get(settings.AXES_USERNAME_FORM_FIELD)


class MiddlewareTestCase(AxesTestCase):
    STATUS_SUCCESS = 200
    STATUS_LOCKOUT = 429

    def setUp(self):
        self.request = HttpRequest()

    def test_success_response(self):
        def get_response(request):
            request.axes_locked_out = False
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_SUCCESS)

    def test_lockout_response(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)

    @override_settings(AXES_USERNAME_CALLABLE="tests.test_middleware.get_username")
    def test_lockout_response_with_axes_callable_username(self):
        def get_response(request):
            request.axes_locked_out = True
            request.axes_credentials = {settings.AXES_USERNAME_FORM_FIELD: 'username'}

            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)

    @override_settings(AXES_ENABLED=False)
    def test_respects_enabled_switch(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_SUCCESS)
