from unittest.mock import patch, MagicMock

from django.http import HttpResponse
from django.test import TestCase

from axes.exceptions import AxesSignalPermissionDenied
from axes.middleware import AxesMiddleware


class MiddlewareTestCase(TestCase):
    SUCCESS_RESPONSE = HttpResponse(status=200, content='Dispatched')
    LOCKOUT_RESPONSE = HttpResponse(status=403, content='Locked out')

    def setUp(self):
        self.request = MagicMock()
        self.get_response = MagicMock()

    @patch('axes.middleware.get_lockout_response', return_value=LOCKOUT_RESPONSE)
    def test_process_exception_axes(self, _):
        exception = AxesSignalPermissionDenied()
        response = AxesMiddleware(self.get_response).process_exception(self.request, exception)
        self.assertEqual(response, self.LOCKOUT_RESPONSE)

    @patch('axes.middleware.get_lockout_response', return_value=LOCKOUT_RESPONSE)
    def test_process_exception_other(self, _):
        exception = Exception()
        response = AxesMiddleware(self.get_response).process_exception(self.request, exception)
        self.assertEqual(response, None)
