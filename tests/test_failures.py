from axes.models import AccessFailureLog
from tests.base import AxesTestCase
from axes.helpers import get_failure_limit
from django.test import override_settings

@override_settings(AXES_ENABLE_ACCESS_FAILURE_LOG=True)
class FailureLogTestCase(AxesTestCase):
    def test_failure_log(self):
        self.login(is_valid_username=True, is_valid_password=False)
        self.assertEqual(AccessFailureLog.objects.count(), 1)
        self.assertTrue(AccessFailureLog.objects.filter(username=self.VALID_USERNAME).exists())
        self.assertTrue(AccessFailureLog.objects.filter(ip_address=self.ip_address).exists())

    def test_failure_locked_out(self):
        self.check_lockout()
        self.assertEqual(AccessFailureLog.objects.filter(locked_out=True).count(), 1)
