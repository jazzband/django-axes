from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest

from axes.attempts import (
    is_user_attempt_whitelisted,
    reset,
)
from axes.models import AccessAttempt
from axes.tests.base import AxesTestCase


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
