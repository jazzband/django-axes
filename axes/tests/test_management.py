from io import StringIO
from unittest.mock import patch, Mock

from django.core.management import call_command
from django.utils import timezone

from axes.models import AccessAttempt, AccessLog
from axes.tests.base import AxesTestCase


class ResetAccessLogsManagementCommandTestCase(AxesTestCase):
    def setUp(self):
        self.msg_not_found = "No logs found.\n"
        self.msg_num_found = "{} logs removed.\n"

        days_3 = timezone.now() - timezone.timedelta(days=3)
        with patch("django.utils.timezone.now", Mock(return_value=days_3)):
            AccessLog.objects.create()

        days_13 = timezone.now() - timezone.timedelta(days=9)
        with patch("django.utils.timezone.now", Mock(return_value=days_13)):
            AccessLog.objects.create()

        days_30 = timezone.now() - timezone.timedelta(days=27)
        with patch("django.utils.timezone.now", Mock(return_value=days_30)):
            AccessLog.objects.create()

    def test_axes_delete_access_logs_default(self):
        out = StringIO()
        call_command("axes_reset_logs", stdout=out)
        self.assertEqual(self.msg_not_found, out.getvalue())

    def test_axes_delete_access_logs_older_than_2_days(self):
        out = StringIO()
        call_command("axes_reset_logs", age=2, stdout=out)
        self.assertEqual(self.msg_num_found.format(3), out.getvalue())

    def test_axes_delete_access_logs_older_than_4_days(self):
        out = StringIO()
        call_command("axes_reset_logs", age=4, stdout=out)
        self.assertEqual(self.msg_num_found.format(2), out.getvalue())

    def test_axes_delete_access_logs_older_than_16_days(self):
        out = StringIO()
        call_command("axes_reset_logs", age=16, stdout=out)
        self.assertEqual(self.msg_num_found.format(1), out.getvalue())


class ManagementCommandTestCase(AxesTestCase):
    def setUp(self):
        AccessAttempt.objects.create(
            username="jane.doe", ip_address="10.0.0.1", failures_since_start="4"
        )

        AccessAttempt.objects.create(
            username="john.doe", ip_address="10.0.0.2", failures_since_start="15"
        )

    def test_axes_list_attempts(self):
        out = StringIO()
        call_command("axes_list_attempts", stdout=out)

        expected = "10.0.0.1\tjane.doe\t4\n10.0.0.2\tjohn.doe\t15\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset(self):
        out = StringIO()
        call_command("axes_reset", stdout=out)

        expected = "2 attempts removed.\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_not_found(self):
        out = StringIO()
        call_command("axes_reset", stdout=out)

        out = StringIO()
        call_command("axes_reset", stdout=out)

        expected = "No attempts found.\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_ip(self):
        out = StringIO()
        call_command("axes_reset_ip", "10.0.0.1", stdout=out)

        expected = "1 attempts removed.\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_ip_not_found(self):
        out = StringIO()
        call_command("axes_reset_ip", "10.0.0.3", stdout=out)

        expected = "No attempts found.\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_username(self):
        out = StringIO()
        call_command("axes_reset_username", "john.doe", stdout=out)

        expected = "1 attempts removed.\n"
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_username_not_found(self):
        out = StringIO()
        call_command("axes_reset_username", "ivan.renko", stdout=out)

        expected = "No attempts found.\n"
        self.assertEqual(expected, out.getvalue())
