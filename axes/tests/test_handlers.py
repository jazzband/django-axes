from unittest.mock import MagicMock, patch

from django.http import HttpRequest
from django.test import TestCase, override_settings

from axes.handlers.proxy import AxesProxyHandler
from axes.models import AccessAttempt


class AxesBaseHandlerTestCase(TestCase):
    @override_settings(AXES_HANDLER='axes.handlers.base.AxesBaseHandler')
    def test_base_handler_raises_on_undefined_is_allowed_to_authenticate(self):
        with self.assertRaises(NotImplementedError):
            AxesProxyHandler.is_allowed_to_authenticate(HttpRequest(), {})


class AxesProxyHandlerTestCase(TestCase):
    def setUp(self):
        self.sender = MagicMock()
        self.credentials = MagicMock()
        self.request = MagicMock()
        self.user = MagicMock()
        self.instance = MagicMock()

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation', None)
    def test_setting_changed_signal_triggers_handler_reimport(self):
            self.assertIsNone(AxesProxyHandler.implementation)

            with self.settings(AXES_HANDLER='axes.handlers.database.AxesDatabaseHandler'):
                self.assertIsNotNone(AxesProxyHandler.implementation)

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation')
    def test_user_login_failed(self, handler):
        self.assertFalse(handler.user_login_failed.called)
        AxesProxyHandler.user_login_failed(self.sender, self.credentials, self.request)
        self.assertTrue(handler.user_login_failed.called)

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation')
    def test_user_logged_in(self, handler):
        self.assertFalse(handler.user_logged_in.called)
        AxesProxyHandler.user_logged_in(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_in.called)

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation')
    def test_user_logged_out(self, handler):
        self.assertFalse(handler.user_logged_out.called)
        AxesProxyHandler.user_logged_out(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_out.called)

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation')
    def test_post_save_access_attempt(self, handler):
        self.assertFalse(handler.post_save_access_attempt.called)
        AxesProxyHandler.post_save_access_attempt(self.instance)
        self.assertTrue(handler.post_save_access_attempt.called)

    @patch('axes.handlers.proxy.AxesProxyHandler.implementation')
    def test_post_delete_access_attempt(self, handler):
        self.assertFalse(handler.post_delete_access_attempt.called)
        AxesProxyHandler.post_delete_access_attempt(self.instance)
        self.assertTrue(handler.post_delete_access_attempt.called)


class AxesDatabaseHandlerTestCase(TestCase):
    def setUp(self):
        self.attempt = AccessAttempt.objects.create(
            username='jane.doe',
            ip_address='127.0.0.1',
            user_agent='test-browser',
            failures_since_start=42,
        )

        self.request = HttpRequest()
        self.request.method = 'POST'
        self.request.META['REMOTE_ADDR'] = '127.0.0.1'

    @patch('axes.handlers.database.log')
    def test_user_login_failed_no_request(self, log):
        AxesProxyHandler.user_login_failed(sender=None, credentials={}, request=None)
        log.warning.assert_called_with(
            'AXES: AxesDatabaseHandler.user_login_failed does not function without a request.'
        )

    @patch('axes.handlers.database.get_client_ip_address', return_value='127.0.0.1')
    @patch('axes.handlers.database.is_client_ip_address_whitelisted', return_value=True)
    @patch('axes.handlers.database.log')
    def test_user_login_failed_whitelist(self, log, _, __):
        AxesProxyHandler.user_login_failed(sender=None, credentials={}, request=self.request)
        log.info.assert_called_with('AXES: Login failed from whitelisted IP %s.', '127.0.0.1')

    @patch('axes.handlers.database.get_axes_cache')
    def test_post_save_access_attempt_updates_cache(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = None
        cache.set.return_value = None

        get_cache.return_value = cache

        self.assertFalse(cache.get.call_count)
        self.assertFalse(cache.set.call_count)

        AxesProxyHandler.post_save_access_attempt(self.attempt)

        self.assertTrue(cache.get.call_count)
        self.assertTrue(cache.set.call_count)

    @patch('axes.handlers.database.get_axes_cache')
    def test_user_login_failed_utilizes_cache(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 1
        get_cache.return_value = cache

        sender = MagicMock()
        credentials = {'username': self.attempt.username}

        self.assertFalse(cache.get.call_count)

        AxesProxyHandler.user_login_failed(sender, credentials, self.request)

        self.assertTrue(cache.get.call_count)

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=True)
    @override_settings(AXES_FAILURE_LIMIT=40)
    @patch('axes.handlers.database.get_axes_cache')
    def test_is_already_locked_cache(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 42
        get_cache.return_value = cache

        self.assertFalse(AxesProxyHandler.is_allowed_to_authenticate(self.request, {}))

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    @override_settings(AXES_FAILURE_LIMIT=40)
    @patch('axes.handlers.database.get_axes_cache')
    def test_is_already_locked_do_not_lock_out_at_failure(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 42
        get_cache.return_value = cache

        self.assertTrue(AxesProxyHandler.is_allowed_to_authenticate(self.request, {}))

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_already_locked_never_lockout_get(self):
        self.request.method = 'GET'

        self.assertTrue(AxesProxyHandler.is_allowed_to_authenticate(self.request, {}))
