from asgiref.sync import async_to_sync
from django.conf import settings
from django.http import HttpResponse, HttpRequest
from django.test import override_settings

from axes.middleware import AxesMiddleware
from tests.base import AxesTestCase


def get_username(request, credentials: dict) -> str:
    return credentials.get(settings.AXES_USERNAME_FORM_FIELD)


LOCKOUT_CALLABLE_ARGUMENTS: list = []


def record_lockout_response(request, original_response, credentials):
    LOCKOUT_CALLABLE_ARGUMENTS.append((original_response, credentials))
    return HttpResponse(status=429)


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

    def test_async_lockout_response(self):
        async def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = async_to_sync(AxesMiddleware(get_response))(self.request)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)

    @override_settings(AXES_USERNAME_CALLABLE="tests.test_middleware.get_username")
    def test_async_lockout_response_with_axes_callable_username(self):
        async def get_response(request):
            request.axes_locked_out = True
            request.axes_credentials = {settings.AXES_USERNAME_FORM_FIELD: "username"}

            return HttpResponse()

        response = async_to_sync(AxesMiddleware(get_response))(self.request)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="tests.test_middleware.record_lockout_response"
    )
    def test_async_lockout_callable_gets_original_response_and_credentials(self):
        LOCKOUT_CALLABLE_ARGUMENTS.clear()
        credentials = {settings.AXES_USERNAME_FORM_FIELD: "username"}
        original_response = HttpResponse()

        async def get_response(request):
            request.axes_locked_out = True
            request.axes_credentials = credentials

            return original_response

        async_to_sync(AxesMiddleware(get_response))(self.request)
        self.assertEqual(LOCKOUT_CALLABLE_ARGUMENTS, [(original_response, credentials)])
