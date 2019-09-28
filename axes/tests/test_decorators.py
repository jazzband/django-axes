from unittest.mock import MagicMock, patch

from django.http import HttpResponse

from axes.decorators import axes_dispatch, axes_form_invalid
from axes.tests.base import AxesTestCase


class DecoratorTestCase(AxesTestCase):
    SUCCESS_RESPONSE = HttpResponse(status=200, content="Dispatched")
    LOCKOUT_RESPONSE = HttpResponse(status=403, content="Locked out")

    def setUp(self):
        self.request = MagicMock()
        self.cls = MagicMock(return_value=self.request)
        self.func = MagicMock(return_value=self.SUCCESS_RESPONSE)

    @patch("axes.handlers.proxy.AxesProxyHandler.is_allowed", return_value=False)
    @patch("axes.decorators.get_lockout_response", return_value=LOCKOUT_RESPONSE)
    def test_axes_dispatch_locks_out(self, _, __):
        response = axes_dispatch(self.func)(self.request)
        self.assertEqual(response.content, self.LOCKOUT_RESPONSE.content)

    @patch("axes.handlers.proxy.AxesProxyHandler.is_allowed", return_value=True)
    @patch("axes.decorators.get_lockout_response", return_value=LOCKOUT_RESPONSE)
    def test_axes_dispatch_dispatches(self, _, __):
        response = axes_dispatch(self.func)(self.request)
        self.assertEqual(response.content, self.SUCCESS_RESPONSE.content)

    @patch("axes.handlers.proxy.AxesProxyHandler.is_allowed", return_value=False)
    @patch("axes.decorators.get_lockout_response", return_value=LOCKOUT_RESPONSE)
    def test_axes_form_invalid_locks_out(self, _, __):
        response = axes_form_invalid(self.func)(self.cls)
        self.assertEqual(response.content, self.LOCKOUT_RESPONSE.content)

    @patch("axes.handlers.proxy.AxesProxyHandler.is_allowed", return_value=True)
    @patch("axes.decorators.get_lockout_response", return_value=LOCKOUT_RESPONSE)
    def test_axes_form_invalid_dispatches(self, _, __):
        response = axes_form_invalid(self.func)(self.cls)
        self.assertEqual(response.content, self.SUCCESS_RESPONSE.content)
