import random
import string
import time

from django.test import TestCase
from django.test.utils import override_settings
from django.contrib.auth.models import User
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse
from django.utils import six

from axes.decorators import COOLOFF_TIME
from axes.decorators import FAILURE_LIMIT
from axes.decorators import is_valid_public_ip
from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
from axes.utils import reset


class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing
    """
    VALID_USERNAME = 'valid-username'
    VALID_PASSWORD = 'valid-password'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'

    def _login(self, is_valid_username=False, is_valid_password=False, user_agent='test-browser', **kwargs):
        """Login a user. A valid credential is used when is_valid_username is True,
        otherwise it will use a random string to make a failed login.
        """
        try:
            admin_login = reverse('admin:login')
        except NoReverseMatch:
            admin_login = reverse('admin:index')

        if is_valid_username:
            # Use a valid username
            username = self.VALID_USERNAME
        else:
            # Generate a wrong random username
            chars = string.ascii_uppercase + string.digits
            username = ''.join(random.choice(chars) for x in range(10))

        if is_valid_password:
            password = self.VALID_PASSWORD
        else:
            password = 'invalid-password'

        post_data = {
            'username': username,
            'password': password,
            'this_is_the_login_form': 1,
        }
        post_data.update(kwargs)
        response = self.client.post(admin_login, post_data, HTTP_USER_AGENT=user_agent)

        return response

    def setUp(self):
        """Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username=self.VALID_USERNAME,
            email='test@example.com',
            password=self.VALID_PASSWORD,
        )

    def test_failure_limit_once(self):
        """Tests the login lock trying to login one more time
        than failure limit
        """
        for i in range(1, FAILURE_LIMIT):  # test until one try before the limit
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_failure_limit_many(self):
        """Tests the login lock trying to login a lot of times more
        than failure limit
        """
        for i in range(1, FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # We should get a locked message each time we try again
        for i in range(0, random.randrange(1, FAILURE_LIMIT)):
            response = self._login()
            self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_valid_login(self):
        """Tests a valid login for a real username
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    def test_valid_logout(self):
        """Tests a valid logout and make sure the logout_time is updated
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
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
        response = self._login(is_valid_username=True, is_valid_password=True, user_agent=long_user_agent)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    def test_long_user_agent_not_valid(self):
        """Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for i in range(0, FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

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

    def test_send_lockout_signal(self):
        """Test if the lockout signal is emitted
        """
        class Scope(object): pass  # this "hack" is needed so we don't have to use global variables or python3 features
        scope = Scope()
        scope.signal_received = 0

        def signal_handler(request, username, ip_address, *args, **kwargs):
            scope.signal_received += 1
            self.assertIsNotNone(request)

        # Connect signal handler
        user_locked_out.connect(signal_handler)

        # Make a lockout
        self.test_failure_limit_once()
        self.assertEquals(scope.signal_received, 1)

        reset()

        # Make another lockout
        self.test_failure_limit_once()
        self.assertEquals(scope.signal_received, 2)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_combination_user_and_ip(self):
        """Tests the login lock with a valid username and invalid password
        when AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True
        """
        for i in range(1, FAILURE_LIMIT):  # test until one try before the limit
            response = self._login(is_valid_username=True, is_valid_password=False)
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_log_data_truncated(self):
        """Tests that query2str properly truncates data to the max_length (default 1024)
        """
        extra_data = {string.ascii_letters * x: x for x in range(0, 1000)}  # An impossibly large post dict
        self._login(**extra_data)
        self.assertEquals(len(AccessAttempt.objects.latest('id').post_data), 1024)


class IPClassifierTest(TestCase):

    def test_classify_private_ips(self):
        """Tests whether is_valid_public_ip correctly classifies IPs as being
        bot public and valid
        """
        EXPECTED = {
            'foobar': False,  # invalid - not octects
            '192.168.0': False,  # invalid - only 3 octets
            '192.168.0.0': False,  # private
            '192.168.165.1': False,  # private
            '192.249.19.1': True,  # public but 192 prefix
            '10.0.201.13': False,  # private
            '172.15.12.1': True,  # public but 172 prefix
            '172.16.12.1': False,  # private
            '172.31.12.1': False,  # private
            '172.32.0.1': True,  # public but 127 prefix
            '200.150.23.5': True,  # normal public
        }
        for ip_address, is_valid_public in six.iteritems(EXPECTED):
            self.assertEqual(is_valid_public_ip(ip_address), is_valid_public)
