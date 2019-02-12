from unittest.mock import MagicMock, patch

from django.http import HttpRequest
from django.test import TestCase, override_settings

from axes.handlers import AxesHandler
from axes.signals import ProxyHandler


class ProxyHandlerTestCase(TestCase):
    def setUp(self):
        self.sender = MagicMock()
        self.credentials = MagicMock()
        self.request = MagicMock()
        self.user = MagicMock()
        self.instance = MagicMock()

    @patch('axes.signals.ProxyHandler.implementation', None)
    @patch('axes.signals.import_string', return_value=AxesHandler)
    def test_initialize(self, importer):
        self.assertEqual(0, importer.call_count)
        self.assertIsNone(ProxyHandler.implementation)

        ProxyHandler.initialize()

        self.assertEqual(1, importer.call_count)
        self.assertIsInstance(ProxyHandler.implementation, AxesHandler)

        ProxyHandler.initialize()

        self.assertEqual(1, importer.call_count)
        self.assertIsInstance(ProxyHandler.implementation, AxesHandler)

    @patch('axes.signals.ProxyHandler.implementation')
    def test_user_login_failed(self, handler):
        self.assertFalse(handler.user_login_failed.called)
        ProxyHandler().user_login_failed(self.sender, self.credentials, self.request)
        self.assertTrue(handler.user_login_failed.called)

    @patch('axes.signals.ProxyHandler.implementation')
    def test_user_logged_in(self, handler):
        self.assertFalse(handler.user_logged_in.called)
        ProxyHandler().user_logged_in(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_in.called)

    @patch('axes.signals.ProxyHandler.implementation')
    def test_user_logged_out(self, handler):
        self.assertFalse(handler.user_logged_out.called)
        ProxyHandler().user_logged_out(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_out.called)

    @patch('axes.signals.ProxyHandler.implementation')
    def test_post_save_access_attempt(self, handler):
        self.assertFalse(handler.post_save_access_attempt.called)
        ProxyHandler().post_save_access_attempt(self.instance)
        self.assertTrue(handler.post_save_access_attempt.called)

    @patch('axes.signals.ProxyHandler.implementation')
    def test_post_delete_access_attempt(self, handler):
        self.assertFalse(handler.post_delete_access_attempt.called)
        ProxyHandler().post_delete_access_attempt(self.instance)
        self.assertTrue(handler.post_delete_access_attempt.called)


class AxesHandlerTestCase(TestCase):
    def setUp(self):
        self.handler = AxesHandler()

    @patch('axes.handlers.log')
    def test_user_login_failed_no_request(self, log):
        self.handler.user_login_failed(sender=None, credentials=None, request=None)
        log.warning.assert_called_with('AxesHandler.user_login_failed does not function without a request.')

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=['127.0.0.1'])
    @patch('axes.handlers.get_client_ip', return_value='127.0.0.1')
    @patch('axes.handlers.ip_in_whitelist', return_value=True)
    @patch('axes.handlers.log')
    def test_user_login_failed_whitelist(self, log, _, __):
        request = HttpRequest()
        self.handler.user_login_failed(sender=None, credentials=None, request=request)
        log.info.assert_called_with('Login failed from whitelisted IP %s.', '127.0.0.1')
