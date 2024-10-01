from unittest.mock import patch

from django.test import override_settings

from axes import __version__
from axes.apps import AppConfig
from axes.models import AccessAttempt, AccessLog
from tests.base import AxesTestCase

_BEGIN = "AXES: BEGIN version %s, %s"
_VERSION = __version__


@patch("axes.apps.AppConfig.initialized", False)
@patch("axes.apps.log")
class AppsTestCase(AxesTestCase):
    def test_axes_config_log_re_entrant(self, log):
        """
        Test that initialize call count does not increase on repeat calls.
        """

        AppConfig.initialize()
        calls = log.info.call_count

        AppConfig.initialize()
        self.assertTrue(
            calls == log.info.call_count and calls > 0,
            "AxesConfig.initialize needs to be re-entrant",
        )

    @override_settings(AXES_VERBOSE=False)
    def test_axes_config_log_not_verbose(self, log):
        AppConfig.initialize()
        self.assertFalse(log.info.called)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_axes_config_log_user_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by username")

    def test_axes_config_log_ip_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by ip_address")

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_axes_config_log_user_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(
            _BEGIN, _VERSION, "blocking by combination of username and ip_address"
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_axes_config_log_user_or_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by username or ip_address")


class AccessLogTestCase(AxesTestCase):
    def test_access_log_on_logout(self):
        """
        Test a valid logout and make sure the logout_time is updated only for that.
        """

        self.login(is_valid_username=True, is_valid_password=True)
        latest_log = AccessLog.objects.latest("id")
        self.assertIsNone(latest_log.logout_time)
        other_log = self.create_log(session_hash='not-the-session')
        self.assertIsNone(other_log.logout_time)

        response = self.logout()
        self.assertContains(response, "Logged out")
        other_log.refresh_from_db()
        self.assertIsNone(other_log.logout_time)
        latest_log.refresh_from_db()
        self.assertIsNotNone(latest_log.logout_time)

    @override_settings(DATA_UPLOAD_MAX_NUMBER_FIELDS=1500)
    def test_log_data_truncated(self):
        """
        Test that get_query_str properly truncates data to the max_length (default 1024).
        """

        # An impossibly large post dict
        extra_data = {"too-large-field": "x" * 2 ** 16}
        self.login(**extra_data)
        self.assertEqual(len(AccessAttempt.objects.latest("id").post_data), 1024)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_success_log(self):
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)
        response = self.logout()

        self.assertEqual(AccessLog.objects.all().count(), 0)
        self.assertContains(response, "Logged out", html=True)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_login_without_success_log(self):
        """
        Test that a valid login does not generate an AccessLog when DISABLE_SUCCESS_ACCESS_LOG is True.
        """

        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccessLog.objects.all().count(), 0)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_log(self):
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)
        response = self.logout()

        self.assertEqual(AccessLog.objects.count(), 0)
        self.assertContains(response, "Logged out", html=True)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_non_valid_login_without_log(self):
        """
        Test that a non-valid login does generate an AccessLog when DISABLE_ACCESS_LOG is True.
        """
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=False)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(AccessLog.objects.all().count(), 0)
