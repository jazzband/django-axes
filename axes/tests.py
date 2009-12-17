from django.test import TestCase, Client
from django.conf import settings
from django.contrib import admin
import random
from django.contrib.auth.models import User

from models import AccessAttempt
from decorators import FAILURE_LIMIT

# Only run tests if they have axes in middleware

# Basically a functional test
class AccessAttemptTest(TestCase):
    NOT_GONNA_BE_PASSWORD = "sfdlermmvnLsefrlg0c9gjjPxmvLlkdf2#"
    NOT_GONNA_BE_USERNAME = "whywouldyouohwhy"

    def setUp(self):
        for i in range(0, random.randrange(10, 50)):
            username = "person%s" % i
            email = "%s@example.org" % username
            u = User.objects.create_user(email=email, username=username)
            u.is_staff = True
            u.save()

    def _gen_bad_password(self):
        return AccessAttemptTest.NOT_GONNA_BE_PASSWORD + str(random.random())

    def _random_username(self, correct_username=False):
        if not correct_username:
            return (AccessAttemptTest.NOT_GONNA_BE_USERNAME +
                    str(random.random()))[:30]
        else:
            return random.choice(User.objects.filter(is_staff=True))

    def _attempt_login(self, correct_username=False, user=""):
        response = self.client.post(
        '/admin/', {'username': self._random_username(correct_username),
                    'password': self._gen_bad_password()}
         )
        return response

    def test_login_max(self, correct_username=False):
        for i in range(0, FAILURE_LIMIT):
            response = self._attempt_login(correct_username=correct_username)
            self.assertContains(response, "this_is_the_login_form")
        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._attempt_login()
        self.assertContains(response, "Account locked")

    def test_login_max_with_more(self, correct_username=False):
        for i in range(0, FAILURE_LIMIT):
            response = self._attempt_login(correct_username=correct_username)
            self.assertContains(response, "this_is_the_login_form")
        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        for i in range(0, random.randrange(1, 100)):
            # try to log in a bunch of times
            response = self._attempt_login()
            self.assertContains(response, "Account locked")

    def test_with_real_username_max(self):
        self.test_login_max(correct_username=True)

    def test_with_real_username_max_with_more(self):
        self.test_login_max_with_more(correct_username=True)
