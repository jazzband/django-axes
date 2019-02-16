from unittest.mock import patch

from django.test import TestCase, override_settings

from axes.apps import AppConfig


@patch('axes.apps.AppConfig.logging_initialized', False)
@patch('axes.apps.log')
class AppsTestCase(TestCase):
    def test_axes_config_log_re_entrant(self, log):
        """
        Test that initialize call count does not increase on repeat calls.
        """

        AppConfig.initialize()
        calls = log.info.call_count

        AppConfig.initialize()
        self.assertTrue(
            calls == log.info.call_count and calls > 0,
            'AxesConfig.initialize needs to be re-entrant',
        )

    @override_settings(AXES_VERBOSE=False)
    def test_axes_config_log_not_verbose(self, log):
        AppConfig.initialize()
        self.assertFalse(log.info.called)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_axes_config_log_user_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with('AXES: blocking by username only.')

    @override_settings(AXES_ONLY_USER_FAILURES=False)
    def test_axes_config_log_ip_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with('AXES: blocking by IP only.')

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_axes_config_log_user_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with('AXES: blocking by combination of username and IP.')
