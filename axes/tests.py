import random
import string
import time

from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse

from axes.decorators import COOLOFF_TIME
from axes.decorators import FAILURE_LIMIT
from axes.decorators import LOGIN_FORM_KEY
from axes.models import AccessLog
from axes.utils import reset


class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing
    """
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'

    def _generate_random_string(self):
        """Generates a random string
        """
        chars = string.ascii_uppercase + string.digits

        return ''.join(random.choice(chars) for x in range(20))

    def _random_username(self, existing_username=False):
        """Returns a username, existing or not depending on params
        """
        if existing_username:
            return User.objects.order_by('?')[0].username

        return self._generate_random_string()

    def _login(self, existing_username=False, user_agent='test-browser'):
        response = self.client.post(reverse('admin:index'), {
            'username': self._random_username(existing_username),
            'password': self._generate_random_string(),
            'this_is_the_login_form': 1,
        }, HTTP_USER_AGENT=user_agent)

        return response

    def setUp(self):
        """Creates users for testing the login
        """
        for i in range(0, random.randrange(10, 50)):
            username = 'person%s' % i
            email = '%s@example.org' % username
            u = User.objects.create_user(
                username=username,
                password=username,
                email=email,
            )
            u.is_staff = True
            u.save()

    def test_login_max(self, existing_username=False):
        """Tests the login lock trying to login one more time
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login(existing_username=existing_username)
            # Check if we are in the same login page
            self.assertIn(LOGIN_FORM_KEY, response.content)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertIn(self.LOCKED_MESSAGE, response.content)

    def test_with_real_username_max(self):
        """Tests the login lock with a real username
        """
        self.test_login_max(existing_username=True)

    def test_login_max_with_more_attempts(self, existing_username=False):
        """Tests the login lock trying to login a lot of times more
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login(existing_username=existing_username)
            # Check if we are in the same login page
            self.assertIn(LOGIN_FORM_KEY, response.content)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        for i in range(0, random.randrange(1, 100)):
            # try to log in a bunch of times
            response = self._login()

        self.assertIn(self.LOCKED_MESSAGE, response.content)

    def test_with_real_username_max_with_more(self):
        """Tests the login lock for a bunch of times with a real username
        """
        self.test_login_max_with_more_attempts(existing_username=True)

    def test_valid_login(self):
        """Tests a valid login for a real username
        """
        valid_username = self._random_username(existing_username=True)
        response = self.client.post(reverse('admin:index'), {
            'username': valid_username,
            'password': valid_username,
            'this_is_the_login_form': 1,
        })

        self.assertNotIn(LOGIN_FORM_KEY, response.content)

    def _successful_login(self, username, password):
        c = Client()
        response = c.post('/admin/', {
            'username': username,
            'password': username,
            'this_is_the_login_form': 1,
        })

        return response

    def _unsuccessful_login(self, username):
        c = Client()
        response = c.post('/admin/', {
            'username': username,
            'password': 'wrong',
            'this_is_the_login_form': 1,
        })

        return response

    def test_cooling_off_for_trusted_user(self):
        valid_username = self._random_username(existing_username=True)

        # Test successful login, this makes the user trusted.
        response = self._successful_login(valid_username, valid_username)
        self.assertNotIn(LOGIN_FORM_KEY, response.content)

        self.test_cooling_off(username=valid_username)

    def test_cooling_off(self, username=None):
        if username:
            valid_username = username
        else:
            valid_username = self._random_username(existing_username=True)

        # Test unsuccessful login and stop just before lockout happens
        for i in range(0, FAILURE_LIMIT):
            response = self._unsuccessful_login(valid_username)

            # Check if we are in the same login page
            self.assertIn(LOGIN_FORM_KEY, response.content)

        # Lock out the user
        response = self._unsuccessful_login(valid_username)
        self.assertIn(self.LOCKED_MESSAGE, response.content)

        # Wait for the cooling off period
        time.sleep(COOLOFF_TIME.total_seconds())

        # It should be possible to login again, make sure it is.
        response = self._successful_login(valid_username, valid_username)
        self.assertNotIn(self.LOCKED_MESSAGE, response.content)

    def test_valid_logout(self):
        """Tests a valid logout and make sure the logout_time is updated
        """
        valid_username = self._random_username(existing_username=True)
        response = self.client.post(reverse('admin:index'), {
            'username': valid_username,
            'password': valid_username,
            'this_is_the_login_form': 1,
        }, follow=True)

        self.assertEquals(AccessLog.objects.latest('id').logout_time, None)

        response = self.client.get(reverse('admin:logout'))

        self.assertNotEquals(AccessLog.objects.latest('id').logout_time, None)

        self.assertIn('Logged out', response.content)

    def test_long_user_agent_valid(self):
        """Tests if can handle a long user agent
        """
        long_user_agent = 'ie6' * 1024
        valid_username = self._random_username(existing_username=True)
        response = self.client.post(reverse('admin:index'), {
            'username': valid_username,
            'password': valid_username,
            'this_is_the_login_form': 1,
        }, HTTP_USER_AGENT=long_user_agent)

        self.assertNotIn(LOGIN_FORM_KEY, response.content)

    def test_long_user_agent_not_valid(self):
        """Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for i in range(0, FAILURE_LIMIT):
            response = self._login(
                existing_username=False,
                user_agent=long_user_agent,
            )
            self.assertContains(response, LOGIN_FORM_KEY)

        response = self._login()
        self.assertIn(self.LOCKED_MESSAGE, response.content)

    def test_reset_ip(self):
        """Tests if can reset an ip address
        """
        # Make a lockout
        self.test_with_real_username_max()

        # Reset the ip so we can try again
        reset(ip='127.0.0.1')

        # Make a login attempt again
        self.test_with_real_username_max()

    def test_reset_all(self):
        """Tests if can reset all attempts
        """
        # Make a lockout
        self.test_with_real_username_max()

        # Reset all attempts so we can try again
        reset()

        # Make a login attempt again
        self.test_with_real_username_max()
