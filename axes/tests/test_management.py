from io import StringIO

from django.core.management import call_command

from axes.models import AccessAttempt
from axes.tests.base import AxesTestCase


class ManagementCommandTestCase(AxesTestCase):
    def setUp(self):
        AccessAttempt.objects.create(
            username='jane.doe',
            ip_address='10.0.0.1',
            failures_since_start='4',
        )

        AccessAttempt.objects.create(
            username='john.doe',
            ip_address='10.0.0.2',
            failures_since_start='15',
        )

    def test_axes_list_attempts(self):
        out = StringIO()
        call_command('axes_list_attempts', stdout=out)

        expected = '10.0.0.1\tjane.doe\t4\n10.0.0.2\tjohn.doe\t15\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset(self):
        out = StringIO()
        call_command('axes_reset', stdout=out)

        expected = '2 attempts removed.\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_not_found(self):
        out = StringIO()
        call_command('axes_reset', stdout=out)

        out = StringIO()
        call_command('axes_reset', stdout=out)

        expected = 'No attempts found.\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_ip(self):
        out = StringIO()
        call_command('axes_reset_ip', '10.0.0.1', stdout=out)

        expected = '1 attempts removed.\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_ip_not_found(self):
        out = StringIO()
        call_command('axes_reset_ip', '10.0.0.3', stdout=out)

        expected = 'No attempts found.\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_username(self):
        out = StringIO()
        call_command('axes_reset_username', 'john.doe', stdout=out)

        expected = '1 attempts removed.\n'
        self.assertEqual(expected, out.getvalue())

    def test_axes_reset_username_not_found(self):
        out = StringIO()
        call_command('axes_reset_username', 'ivan.renko', stdout=out)

        expected = 'No attempts found.\n'
        self.assertEqual(expected, out.getvalue())
