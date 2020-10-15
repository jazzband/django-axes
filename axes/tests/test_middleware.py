from unittest import mock

from django.http import HttpResponse, HttpRequest
from django.conf import settings
from django.test import override_settings

from axes.middleware import AxesMiddleware
from axes.tests.base import AxesTestCase


class MiddlewareTestCase(AxesTestCase):
    STATUS_SUCCESS = 200
    STATUS_LOCKOUT = 403

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

    @mock.patch("django.conf.settings.INSTALLED_APPS", ["rest_framework"])
    def test_response_contains_required_attrs_with_drf_integration(self):
        def get_response(request):
            return HttpResponse()

        self.assertFalse(hasattr(self.request, "axes_locked_out"))
        self.assertFalse(hasattr(self.request, "axes_attempt_time"))
        self.assertFalse(hasattr(self.request, "axes_ip_address"))
        self.assertFalse(hasattr(self.request, "axes_user_agent"))
        self.assertFalse(hasattr(self.request, "axes_path_info"))
        self.assertFalse(hasattr(self.request, "axes_http_accept"))
        self.assertFalse(hasattr(self.request, "axes_updated"))

        AxesMiddleware(get_response)(self.request)

        self.assertTrue(hasattr(self.request, "axes_locked_out"))
        self.assertTrue(hasattr(self.request, "axes_attempt_time"))
        self.assertTrue(hasattr(self.request, "axes_ip_address"))
        self.assertTrue(hasattr(self.request, "axes_user_agent"))
        self.assertTrue(hasattr(self.request, "axes_path_info"))
        self.assertTrue(hasattr(self.request, "axes_http_accept"))
        self.assertTrue(hasattr(self.request, "axes_updated"))

    def test_response_does_not_contain_extra_attrs_without_drf_integration(
        self,
    ):
        def get_response(request):
            return HttpResponse()

        self.assertNotIn("rest_framework", settings.INSTALLED_APPS)

        AxesMiddleware(get_response)(self.request)

        self.assertFalse(hasattr(self.request, "axes_locked_out"))
        self.assertFalse(hasattr(self.request, "axes_attempt_time"))
        self.assertFalse(hasattr(self.request, "axes_ip_address"))
        self.assertFalse(hasattr(self.request, "axes_user_agent"))
        self.assertFalse(hasattr(self.request, "axes_path_info"))
        self.assertFalse(hasattr(self.request, "axes_http_accept"))
        self.assertFalse(hasattr(self.request, "axes_updated"))

    @mock.patch("axes.middleware.get_failure_limit", return_value=5)
    @mock.patch("axes.middleware.AxesProxyHandler.get_failures", return_value=5)
    @mock.patch("django.conf.settings.INSTALLED_APPS", ["rest_framework"])
    @override_settings(AXES_LOCK_OUT_AT_FAILURE=True)
    def test_lockout_response_with_drf_integration(
        self, mock_get_failure_limit, mock_get_failures
    ):
        def get_response(request):
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertTrue(hasattr(self.request, "axes_locked_out"))
        self.assertTrue(self.request.axes_locked_out)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)

    @mock.patch("axes.middleware.get_failure_limit", return_value=5)
    @mock.patch("axes.middleware.AxesProxyHandler.get_failures", return_value=3)
    @mock.patch("django.conf.settings.INSTALLED_APPS", ["rest_framework"])
    @override_settings(AXES_LOCK_OUT_AT_FAILURE=True)
    def test_success_response_with_drf_integration(
        self, mock_get_failure_limit, mock_get_failures
    ):
        def get_response(request):
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertTrue(hasattr(self.request, "axes_locked_out"))
        self.assertFalse(self.request.axes_locked_out)
        self.assertEqual(response.status_code, self.STATUS_SUCCESS)
