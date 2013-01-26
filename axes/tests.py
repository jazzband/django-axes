# Only run tests if they have axes in middleware

# Basically a functional test

import random
import string

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test.utils import override_settings


FAILURE_LIMIT = 3


@override_settings(
    AXES_LOGIN_FAILURE_LIMIT=FAILURE_LIMIT,
    AXES_LOCKOUT_URL=None,
    AXES_USE_USER_AGENT=False,
    AXES_COOLOFF_TIME=None,
    AXES_LOCKOUT_TEMPLATE=None,
)
class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing"""

    def setUp(self):
        for i in range(0, random.randrange(10, 50)):
            username = "person%s" % i
            email = "%s@example.org" % username
            u = User.objects.create_user(email=email, username=username)
            u.is_staff = True
            u.save()

    def _generate_random_string(self):
        """Generates a random string"""
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
            for x in range(20))

    def _random_username(self, existing_username=False):
        """Returns a username, existing or not depending on params"""
        if existing_username:
            return User.objects.order_by('?')[0].username

        return self._generate_random_string()

    def _attempt_login(self, existing_username=False):
        response = self.client.post(reverse('admin:index'), {
            'username': self._random_username(existing_username),
            'password': self._generate_random_string()
        })

        return response

    def test_login_max(self, existing_username=False):
        for i in range(0, FAILURE_LIMIT - 1):
            response = self._attempt_login(existing_username=existing_username)
            # Check if we are in the same login page
            self.assertEquals(response.status_code, 200)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._attempt_login()
        self.assertContains(response, 'Account locked')

    def test_with_real_username_max(self):
        self.test_login_max(existing_username=True)

    def test_login_max_with_more_attempts(self, existing_username=False):
        for i in range(0, FAILURE_LIMIT - 1):
            response = self._attempt_login(existing_username=existing_username)
            # Check if we are in the same login page
            self.assertEquals(response.status_code, 200)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        for i in range(0, random.randrange(1, 100)):
            # try to log in a bunch of times
            response = self._attempt_login()
            self.assertContains(response, 'Account locked')

    def test_with_real_username_max_with_more(self):
        self.test_login_max_with_more_attempts(existing_username=True)
