from unittest.mock import patch

from django.http import HttpRequest
from django.test import override_settings, RequestFactory
from django.utils.timezone import now

from axes.attempts import get_cool_off_threshold
from axes.models import AccessAttempt
from axes.utils import reset, reset_request
from tests.base import AxesTestCase


class GetCoolOffThresholdTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=42)
    def test_get_cool_off_threshold(self):
        timestamp = now()

        request = RequestFactory().post("/")
        with patch("axes.attempts.now", return_value=timestamp):
            request.axes_attempt_time = timestamp
            threshold_now = get_cool_off_threshold(request)

            request.axes_attempt_time = None
            threshold_none = get_cool_off_threshold(request)

        self.assertEqual(threshold_now, threshold_none)

    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cool_off_threshold_error(self):
        with self.assertRaises(TypeError):
            get_cool_off_threshold()


class ResetTestCase(AxesTestCase):
    def test_reset(self):
        self.create_attempt()
        reset()
        self.assertFalse(AccessAttempt.objects.count())

    def test_reset_ip(self):
        self.create_attempt(ip_address=self.ip_address)
        reset(ip=self.ip_address)
        self.assertFalse(AccessAttempt.objects.count())

    def test_reset_username(self):
        self.create_attempt(username=self.username)
        reset(username=self.username)
        self.assertFalse(AccessAttempt.objects.count())


class ResetResponseTestCase(AxesTestCase):
    USERNAME_1 = "foo_username"
    USERNAME_2 = "bar_username"
    IP_1 = "127.1.0.1"
    IP_2 = "127.1.0.2"

    def setUp(self):
        super().setUp()
        self.create_attempt()
        self.create_attempt(username=self.USERNAME_1, ip_address=self.IP_1)
        self.create_attempt(username=self.USERNAME_1, ip_address=self.IP_2)
        self.create_attempt(username=self.USERNAME_2, ip_address=self.IP_1)
        self.create_attempt(username=self.USERNAME_2, ip_address=self.IP_2)
        self.request = HttpRequest()

    def test_reset(self):
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    def test_reset_ip(self):
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    def test_reset_username(self):
        self.request.GET["username"] = self.USERNAME_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    def test_reset_ip_username(self):
        self.request.GET["username"] = self.USERNAME_1
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_reset_user_failures(self):
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_reset_ip_user_failures(self):
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_reset_username_user_failures(self):
        self.request.GET["username"] = self.USERNAME_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_reset_ip_username_user_failures(self):
        self.request.GET["username"] = self.USERNAME_1
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_reset_user_or_ip(self):
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_reset_ip_user_or_ip(self):
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_reset_username_user_or_ip(self):
        self.request.GET["username"] = self.USERNAME_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_reset_ip_username_user_or_ip(self):
        self.request.GET["username"] = self.USERNAME_1
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 2)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_reset_user_and_ip(self):
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 5)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_reset_ip_user_and_ip(self):
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_reset_username_user_and_ip(self):
        self.request.GET["username"] = self.USERNAME_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 3)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_reset_ip_username_user_and_ip(self):
        self.request.GET["username"] = self.USERNAME_1
        self.request.META["REMOTE_ADDR"] = self.IP_1
        reset_request(self.request)
        self.assertEqual(AccessAttempt.objects.count(), 4)
