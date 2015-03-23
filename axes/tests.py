import random
import string
import time

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse

from axes.decorators import COOLOFF_TIME
from axes.decorators import FAILURE_LIMIT
from axes.models import AccessLog
from axes.utils import reset


class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing
    """
    VALID_PASSWORD = 'valid-password'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'

    def _login(self, is_valid=False, user_agent='test-browser'):
        """Login a user. A valid credential is used when is_valid is True,
        otherwise it will use a random string to make a failed login.
        """
        try:
            admin_login = reverse('admin:login')
        except NoReverseMatch:
            admin_login = reverse('admin:index')

        if is_valid:
            # Use a valid username
            username = self.user.username
        else:
            # Generate a wrong random username
            chars = string.ascii_uppercase + string.digits
            username = ''.join(random.choice(chars) for x in range(10))

        response = self.client.post(admin_login, {
            'username': username,
            'password': self.VALID_PASSWORD,
            'this_is_the_login_form': 1,
        }, HTTP_USER_AGENT=user_agent)

        return response

    def setUp(self):
        """Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username='valid-username',
            email='test@example.com',
            password=self.VALID_PASSWORD,
        )

    def test_failure_limit_once(self):
        """Tests the login lock trying to login one more time
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_failure_limit_many(self):
        """Tests the login lock trying to login a lot of times more
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # We should get a locked message each time we try again
        for i in range(0, random.randrange(1, FAILURE_LIMIT)):
            response = self._login()
            self.assertContains(response, self.LOCKED_MESSAGE)

    def test_valid_login(self):
        """Tests a valid login for a real username
        """
        response = self._login(is_valid=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    def test_valid_logout(self):
        """Tests a valid logout and make sure the logout_time is updated
        """
        response = self._login(is_valid=True)
        self.assertEquals(AccessLog.objects.latest('id').logout_time, None)

        response = self.client.get(reverse('admin:logout'))
        self.assertNotEquals(AccessLog.objects.latest('id').logout_time, None)
        self.assertContains(response, 'Logged out')

    def test_cooling_off(self):
        """Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_once()

        # Wait for the cooling off period
        time.sleep(COOLOFF_TIME.total_seconds())

        # It should be possible to login again, make sure it is.
        self.test_valid_login()

    def test_cooling_off_for_trusted_user(self):
        """Test the cooling time for a trusted user
        """
        # Test successful login-logout, this makes the user trusted.
        self.test_valid_logout()

        # Try the cooling off time
        self.test_cooling_off()

    def test_long_user_agent_valid(self):
        """Tests if can handle a long user agent
        """
        long_user_agent = 'ie6' * 1024
        response = self._login(is_valid=True, user_agent=long_user_agent)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    def test_long_user_agent_not_valid(self):
        """Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for i in range(0, FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_reset_ip(self):
        """Tests if can reset an ip address
        """
        # Make a lockout
        self.test_failure_limit_once()

        # Reset the ip so we can try again
        reset(ip='127.0.0.1')

        # Make a login attempt again
        self.test_valid_login()

    def test_reset_all(self):
        """Tests if can reset all attempts
        """
        # Make a lockout
        self.test_failure_limit_once()

        # Reset all attempts so we can try again
        reset()

        # Make a login attempt again
        self.test_valid_login()
