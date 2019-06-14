from unittest.mock import MagicMock, patch

from django.test import override_settings
from django.utils.timezone import timedelta

from axes.conf import settings
from axes.handlers.proxy import AxesProxyHandler
from axes.tests.base import AxesTestCase
from axes.helpers import get_client_str


@override_settings(AXES_HANDLER='axes.handlers.base.AxesHandler')
class AxesHandlerTestCase(AxesTestCase):
    def test_base_handler_raises_on_undefined_is_allowed_to_authenticate(self):
        with self.assertRaises(NotImplementedError):
            AxesProxyHandler.is_allowed(self.request, {})

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.1'])
    def test_is_allowed_with_blacklisted_ip_address(self):
        self.assertFalse(AxesProxyHandler.is_allowed(self.request))

    @override_settings(
        AXES_NEVER_LOCKOUT_WHITELIST=True,
        AXES_IP_WHITELIST=['127.0.0.1'],
    )
    def test_is_allowed_with_whitelisted_ip_address(self):
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_allowed_with_whitelisted_method(self):
        self.request.method = 'GET'
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_is_allowed_no_lock_out(self):
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))


class AxesProxyHandlerTestCase(AxesTestCase):
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


class AxesHandlerBaseTestCase(AxesTestCase):
    def check_whitelist(self, log):
        with override_settings(
            AXES_NEVER_LOCKOUT_WHITELIST=True,
            AXES_IP_WHITELIST=[self.ip_address],
        ):
            AxesProxyHandler.user_login_failed(sender=None, request=self.request, credentials=self.credentials)
            client_str = get_client_str(self.username, self.ip_address, self.user_agent, self.path_info)
            log.info.assert_called_with('AXES: Login failed from whitelisted client %s.', client_str)

    def check_empty_request(self, log, handler):
        AxesProxyHandler.user_login_failed(sender=None, credentials={}, request=None)
        log.error.assert_called_with(f'AXES: {handler}.user_login_failed does not function without a request.')


@override_settings(
    AXES_HANDLER='axes.handlers.database.AxesDatabaseHandler',
    AXES_COOLOFF_TIME=timedelta(seconds=1),
    AXES_RESET_ON_SUCCESS=True,
)
class AxesDatabaseHandlerTestCase(AxesHandlerBaseTestCase):
    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_handler(self):
        self.check_handler()

    @override_settings(AXES_RESET_ON_SUCCESS=False)
    def test_handler_without_reset(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT=lambda *args: 3)
    def test_handler_callable_failure_limit(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT='axes.tests.base.custom_failure_limit')
    def test_handler_str_failure_limit(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT=None)
    def test_handler_invalid_failure_limit(self):
        with self.assertRaises(TypeError):
            self.check_handler()

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_handler_without_lockout(self):
        self.check_handler()

    @patch('axes.handlers.database.log')
    def test_empty_request(self, log):
        self.check_empty_request(log, 'AxesDatabaseHandler')

    @patch('axes.handlers.database.log')
    def test_whitelist(self, log):
        self.check_whitelist(log)

    @patch('axes.handlers.database.is_user_attempt_whitelisted', return_value=True)
    def test_user_whitelisted(self, is_whitelisted):
        self.assertFalse(AxesProxyHandler().is_locked(self.request, self.credentials))
        self.assertEqual(1, is_whitelisted.call_count)


@override_settings(
    AXES_HANDLER='axes.handlers.cache.AxesCacheHandler',
    AXES_COOLOFF_TIME=timedelta(seconds=1),
)
class AxesCacheHandlerTestCase(AxesHandlerBaseTestCase):
    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_handler(self):
        self.check_handler()

    @override_settings(AXES_RESET_ON_SUCCESS=False)
    def test_handler_without_reset(self):
        self.check_handler()

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_handler_without_lockout(self):
        self.check_handler()

    @patch('axes.handlers.cache.log')
    def test_empty_request(self, log):
        self.check_empty_request(log, 'AxesCacheHandler')

    @patch('axes.handlers.cache.log')
    def test_whitelist(self, log):
        self.check_whitelist(log)


@override_settings(
    AXES_HANDLER='axes.handlers.dummy.AxesDummyHandler',
)
class AxesDummyHandlerTestCase(AxesHandlerBaseTestCase):
    def test_handler(self):
        for _ in range(settings.AXES_FAILURE_LIMIT):
            self.login()

        self.check_login()
