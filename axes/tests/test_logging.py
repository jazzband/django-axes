from unittest.mock import patch

from django.test import TestCase, override_settings

from axes.apps import AppConfig


@patch('axes.apps.AppConfig.logging_initialized', False)
@patch('axes.apps.log')
class AppsTestCase(TestCase):
    def test_axes_config_log_re_entrant(self, log):
        """
        Test that log call count does not increase on repeat calls.
        """

        AppConfig.log()
        calls = log.info.call_count

        AppConfig.log()
        self.assertTrue(
            calls == log.info.call_count and calls > 0,
            'AxesConfig.log needs to be re-entrant',
        )

    @override_settings(AXES_VERBOSE=False)
    def test_axes_config_log_not_verbose(self, log):
        AppConfig.log()
        self.assertFalse(log.info.called)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_axes_config_log_user_only(self, log):
        AppConfig.log()
        log.info.assert_called_with('AXES: blocking by username only.')

    @override_settings(AXES_ONLY_USER_FAILURES=False)
    def test_axes_config_log_ip_only(self, log):
        AppConfig.log()
        log.info.assert_called_with('AXES: blocking by IP only.')

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_axes_config_log_user_ip(self, log):
        AppConfig.log()
        log.info.assert_called_with('AXES: blocking by combination of username and IP.')
