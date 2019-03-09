from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import override_settings
from django.utils.timezone import now

from axes.attempts import is_user_attempt_whitelisted, get_cool_off_threshold
from axes.models import AccessAttempt
from axes.tests.base import AxesTestCase
from axes.utils import reset


class GetCoolOffThresholdTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=42)
    def test_get_cool_off_threshold(self):
        timestamp = now()

        with patch('axes.attempts.now', return_value=timestamp):
            attempt_time = timestamp
            threshold_now = get_cool_off_threshold(attempt_time)

            attempt_time = None
            threshold_none = get_cool_off_threshold(attempt_time)

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


class UserWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create(username='jane.doe')
        self.request = HttpRequest()

    def test_is_client_username_whitelisted(self):
        with patch.object(self.user_model, 'nolockout', True, create=True):
            self.assertTrue(is_user_attempt_whitelisted(
                self.request,
                {self.user_model.USERNAME_FIELD: self.user.username},
            ))

    def test_is_client_username_whitelisted_not(self):
        self.assertFalse(is_user_attempt_whitelisted(
            self.request,
            {self.user_model.USERNAME_FIELD: self.user.username},
        ))

    def test_is_client_username_whitelisted_does_not_exist(self):
        self.assertFalse(is_user_attempt_whitelisted(
            self.request,
            {self.user_model.USERNAME_FIELD: 'not.' + self.user.username},
        ))
