from datetime import timedelta

from django.conf import settings
from django.http import HttpResponse, HttpRequest
from django.test import override_settings

from axes.middleware import AxesMiddleware
from tests.base import AxesTestCase


def get_username(request, credentials: dict) -> str:
    return credentials.get(settings.AXES_USERNAME_FORM_FIELD)


def get_custom_lockout_response(request, original_response, credentials):
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

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_ENABLE_RETRY_AFTER_HEADER=True,
    )
    def test_lockout_response_sets_retry_after_header(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response["Retry-After"], "120")

    @override_settings(AXES_COOLOFF_TIME=None)
    def test_lockout_response_without_cooloff_does_not_set_retry_after_header(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_ENABLE_RETRY_AFTER_HEADER=False,
    )
    def test_lockout_response_respects_retry_after_toggle(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_LOCKOUT_URL="https://example.com",
    )
    def test_lockout_redirect_response_does_not_set_retry_after_header(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_LOCKOUT_CALLABLE="tests.test_middleware.get_custom_lockout_response",
    )
    def test_lockout_callable_response_does_not_set_retry_after_header(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(AXES_USERNAME_CALLABLE="tests.test_middleware.get_username")
    def test_lockout_response_with_axes_callable_username(self):
        def get_response(request):
            request.axes_locked_out = True
            request.axes_credentials = {settings.AXES_USERNAME_FORM_FIELD: "username"}

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
