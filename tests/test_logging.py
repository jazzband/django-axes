from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse

from axes.apps import AppConfig
from axes.models import AccessAttempt, AccessLog
from tests.base import AxesTestCase


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

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_axes_config_log_user_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with("AXES: blocking by username only.")

    @override_settings(AXES_ONLY_USER_FAILURES=False)
    def test_axes_config_log_ip_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with("AXES: blocking by IP only.")

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_axes_config_log_user_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with("AXES: blocking by combination of username and IP.")

    @override_settings(AXES_LOCK_OUT_BY_USER_OR_IP=True)
    def test_axes_config_log_user_or_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with("AXES: blocking by username or IP.")


class AccessLogTestCase(AxesTestCase):
    def test_access_log_on_logout(self):
        """
        Test a valid logout and make sure the logout_time is updated.
        """

        self.login(is_valid_username=True, is_valid_password=True)
        self.assertIsNone(AccessLog.objects.latest("id").logout_time)

        response = self.client.get(reverse("admin:logout"))
        self.assertContains(response, "Logged out")

        self.assertIsNotNone(AccessLog.objects.latest("id").logout_time)

    def test_log_data_truncated(self):
        """
        Test that get_query_str properly truncates data to the max_length (default 1024).
        """

        # An impossibly large post dict
        extra_data = {"a" * x: x for x in range(1024)}
        self.login(**extra_data)
        self.assertEqual(len(AccessAttempt.objects.latest("id").post_data), 1024)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_success_log(self):
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)
        response = self.client.get(reverse("admin:logout"))

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
        response = self.client.get(reverse("admin:logout"))

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
