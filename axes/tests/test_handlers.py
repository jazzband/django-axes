from unittest.mock import MagicMock, patch

from django.test import TestCase

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
