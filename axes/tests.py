import random
import string
import time
import json
import datetime

from hashlib import md5
from mock import patch

from django.conf import settings
from django.test import TestCase
from django.contrib.auth.models import User
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse
from django.utils import six
from django.test.client import RequestFactory

from axes.decorators import get_ip, get_cache_key, get_client_str
from axes.settings import FAILURE_LIMIT
from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
from axes.utils import reset, iso8601


TEST_COOLOFF_TIME = datetime.timedelta(seconds=2)


class MockRequest:
    def __init__(self):
        self.META = dict()


class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing
    """
    VALID_USERNAME = 'valid-username'
    VALID_PASSWORD = 'valid-password'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'

    def _login(self, is_valid_username=False, is_valid_password=False,
               is_json=False, **kwargs):
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

        headers = {
            'user_agent': 'test-browser'
        }
        post_data = {
            'username': username,
            'password': password,
            'this_is_the_login_form': 1,
        }
        post_data.update(kwargs)

        if is_json:
            headers.update({
                'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest',
                'content_type': 'application/json',
            })
            post_data = json.dumps(post_data)
        response = self.client.post(admin_login, post_data, **headers)

        return response

    def setUp(self):
        """Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username=self.VALID_USERNAME,
            email='test@example.com',
            password=self.VALID_PASSWORD,
        )

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_failure_limit_once(self, cache_get_mock, cache_set_mock):
        """Tests the login lock trying to login one more time
        than failure limit
        """
        # test until one try before the limit
        for i in range(1, FAILURE_LIMIT):
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

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_valid_login(self, cache_set_mock, cache_get_mock):
        """Tests a valid login for a real username
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_valid_logout(self, cache_set_mock, cache_get_mock):
        """Tests a valid logout and make sure the logout_time is updated
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertEquals(AccessLog.objects.latest('id').logout_time, None)

        response = self.client.get(reverse('admin:logout'))
        self.assertNotEquals(AccessLog.objects.latest('id').logout_time, None)
        self.assertContains(response, 'Logged out')

    @patch('axes.decorators.COOLOFF_TIME', TEST_COOLOFF_TIME)
    def test_cooling_off(self):
        """Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_once()

        # Wait for the cooling off period
        time.sleep(TEST_COOLOFF_TIME.total_seconds())

        # It should be possible to login again, make sure it is.
        self.test_valid_login()

    @patch('axes.decorators.COOLOFF_TIME', TEST_COOLOFF_TIME)
    def test_cooling_off_for_trusted_user(self):
        """Test the cooling time for a trusted user
        """
        # Test successful login-logout, this makes the user trusted.
        self.test_valid_logout()

        # Try the cooling off time
        self.test_cooling_off()

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_long_user_agent_valid(self, cache_set_mock, cache_get_mock):
        """Tests if can handle a long user agent
        """
        long_user_agent = 'ie6' * 1024
        response = self._login(
            is_valid_username=True,
            is_valid_password=True,
            user_agent=long_user_agent,
        )
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

    @patch('axes.decorators.get_ip', return_value='127.0.0.1')
    def test_get_cache_key(self, get_ip_mock):
        """ Test the cache key format"""
        # Getting cache key from request
        ip = '127.0.0.1'.encode('utf-8')

        cache_hash_key_checker = 'axes-{}'.format(md5((ip)).hexdigest())

        request_factory = RequestFactory()
        request = request_factory.post('/admin/login/',
                                       data={
                                           'username': self.VALID_USERNAME,
                                           'password': 'test'
                                       })

        cache_hash_key = get_cache_key(request)
        self.assertEqual(cache_hash_key_checker, cache_hash_key)

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent='<unknown>',
            ip_address='127.0.0.1',
            username=self.VALID_USERNAME,
            get_data='',
            post_data='',
            http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
            path_info=request.META.get('PATH_INFO', '<unknown>'),
            failures_since_start=0,
        )
        cache_hash_key = get_cache_key(attempt)
        self.assertEqual(cache_hash_key_checker, cache_hash_key)

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

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_combination_user_and_ip(self, cache_set_mock,
                                                cache_get_mock):
        """Tests the login lock with a valid username and invalid password
        when AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True
        """
        # test until one try before the limit
        for i in range(1, FAILURE_LIMIT):
            response = self._login(
                is_valid_username=True,
                is_valid_password=False,
            )
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_only(self, cache_set_mock, cache_get_mock):
        """Tests the login lock with a valid username and invalid password
        when AXES_ONLY_USER_FAILURES is True
        """
        # test until one try before the limit
        for i in range(1, FAILURE_LIMIT):
            response = self._login(
                is_valid_username=True,
                is_valid_password=False,
            )
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

        # reset the username only and make sure we can log in now even though our IP has failed each time
        reset(username=AccessAttemptTest.VALID_USERNAME)
        response = self._login(
            is_valid_username=True,
            is_valid_password=True,
        )
        # Check if we are still in the login page
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

        # now create failure_limit + 1 failed logins and then we should still be able to login with valid_username
        for i in range(1, FAILURE_LIMIT + 1):
            response = self._login(
                is_valid_username=False,
                is_valid_password=False,
            )
        # Check if we can still log in with valid user
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302)

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_log_data_truncated(self, cache_set_mock, cache_get_mock):
        """Tests that query2str properly truncates data to the
        max_length (default 1024)
        """
        # An impossibly large post dict
        extra_data = {string.ascii_letters * x: x for x in range(0, 1000)}
        self._login(**extra_data)
        self.assertEquals(
            len(AccessAttempt.objects.latest('id').post_data), 1024
        )

    def test_json_response(self):
        """Tests response content type and status code for the ajax request
        """
        self.test_failure_limit_once()
        response = self._login(is_json=True)
        self.assertEquals(response.status_code, 403)
        self.assertEquals(response.get('Content-Type'), 'application/json')

    @patch('axes.decorators.DISABLE_SUCCESS_ACCESS_LOG', True)
    def test_valid_logout_without_success_log(self):
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)
        response = self.client.get(reverse('admin:logout'))

        self.assertEquals(AccessLog.objects.all().count(), 0)
        self.assertContains(response, 'Logged out')

    @patch('axes.decorators.DISABLE_SUCCESS_ACCESS_LOG', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_non_valid_login_without_success_log(self, cache_set_mock,
                                                 cache_get_mock):
        """
        A non-valid login does generate an AccessLog when
        `DISABLE_SUCCESS_ACCESS_LOG=True`.
        """
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertEquals(response.status_code, 200)

        self.assertEquals(AccessLog.objects.all().count(), 1)

    @patch('axes.decorators.DISABLE_SUCCESS_ACCESS_LOG', True)
    def test_valid_login_without_success_log(self):
        """
        A valid login doesn't generate an AccessLog when
        `DISABLE_SUCCESS_ACCESS_LOG=True`.
        """
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccessLog.objects.all().count(), 0)

    @patch('axes.decorators.DISABLE_ACCESS_LOG', True)
    def test_valid_logout_without_log(self):
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)
        response = self.client.get(reverse('admin:logout'))

        self.assertEquals(AccessLog.objects.all().count(), 0)
        self.assertContains(response, 'Logged out')

    @patch('axes.decorators.DISABLE_ACCESS_LOG', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_non_valid_login_without_log(self, cache_set_mock, cache_get_mock):
        """
        A non-valid login does generate an AccessLog when
        `DISABLE_ACCESS_LOG=True`.
        """
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertEquals(response.status_code, 200)

        self.assertEquals(AccessLog.objects.all().count(), 0)

    @patch('axes.decorators.DISABLE_ACCESS_LOG', True)
    def test_valid_login_without_log(self):
        """
        A valid login doesn't generate an AccessLog when
        `DISABLE_ACCESS_LOG=True`.
        """
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccessLog.objects.all().count(), 0)

    @patch('axes.decorators.DISABLE_ACCESS_LOG', True)
    def test_check_is_not_made_on_GET(self):
        AccessLog.objects.all().delete()

        try:
            admin_login = reverse('admin:login')
        except NoReverseMatch:
            admin_login = reverse('admin:index')

        response = self.client.get(admin_login)
        self.assertEqual(response.status_code, 200)

        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertEqual(response.status_code, 302)

        response = self.client.get(reverse('admin:index'))
        self.assertEqual(response.status_code, 200)


class AccessAttemptConfigTest(TestCase):
    """ This set of tests checks for lockouts under different configurations
    and circumstances to prevent false positives and false negatives.
    Always block attempted logins for the same user from the same IP.
    Always allow attempted logins for a different user from a different IP.
    """

    IP_1 = '10.1.1.1'
    IP_2 = '10.2.2.2'
    USER_1 = 'valid-user-1'
    USER_2 = 'valid-user-2'
    VALID_PASSWORD = 'valid-password'
    WRONG_PASSWORD = 'wrong-password'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'
    ALLOWED = 302
    BLOCKED = 403

    def _login(self, username, password, ip_addr='127.0.0.1',
               is_json=False, **kwargs):
        """Login a user and get the response.
        IP address can be configured to test IP blocking functionality.
        """
        try:
            admin_login = reverse('admin:login')
        except NoReverseMatch:
            admin_login = reverse('admin:index')

        headers = {
            'user_agent': 'test-browser'
        }
        post_data = {
            'username': username,
            'password': password,
            'this_is_the_login_form': 1,
        }
        post_data.update(kwargs)

        if is_json:
            headers.update({
                'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest',
                'content_type': 'application/json',
            })
            post_data = json.dumps(post_data)

        response = self.client.post(
            admin_login, post_data, REMOTE_ADDR=ip_addr, **headers
        )
        return response

    def _lockout_user1_from_ip1(self):
        for i in range(1, FAILURE_LIMIT+1):
            response = self._login(
                username=self.USER_1,
                password=self.WRONG_PASSWORD,
                ip_addr=self.IP_1
            )
        return response

    def setUp(self):
        """Create two valid users for authentication.
        """

        self.user = User.objects.create_superuser(
            username=self.USER_1,
            email='test_1@example.com',
            password=self.VALID_PASSWORD,
        )
        self.user = User.objects.create_superuser(
            username=self.USER_2,
            email='test_2@example.com',
            password=self.VALID_PASSWORD,
        )

    # Test for true and false positives when blocking by IP *OR* user (default).
    # Cache disabled. Default settings.
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_ip_blocks_when_same_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_ip_allows_when_same_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_ip_blocks_when_diff_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_ip_allows_when_diff_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user only.
    # Cache disabled. When AXES_ONLY_USER_FAILURES = True
    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_blocks_when_same_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_allows_when_diff_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user and IP together.
    # Cache disabled. When LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.cache.set', return_value=None)
    @patch('axes.decorators.cache.get', return_value=None)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by IP *OR* user (default).
    # With cache enabled. Default criteria.
    def test_lockout_by_ip_blocks_when_same_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_same_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    def test_lockout_by_ip_blocks_when_diff_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_diff_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user only.
    # With cache enabled. When AXES_ONLY_USER_FAILURES = True
    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    def test_lockout_by_user_blocks_when_same_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    def test_lockout_by_user_allows_when_diff_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user and IP together.
    # With cache enabled. When LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)


class UtilsTest(TestCase):
    def test_iso8601(self):
        """Tests iso8601 correctly translates datetime.timdelta to ISO 8601
        formatted duration."""
        EXPECTED = {
            datetime.timedelta(days=1, hours=25, minutes=42, seconds=8):
                'P2DT1H42M8S',
            datetime.timedelta(days=7, seconds=342):
                'P7DT5M42S',
            datetime.timedelta(days=0, hours=2, minutes=42):
                'PT2H42M',
            datetime.timedelta(hours=20, seconds=42):
                'PT20H42S',
            datetime.timedelta(seconds=300):
                'PT5M',
            datetime.timedelta(seconds=9005):
                'PT2H30M5S',
            datetime.timedelta(minutes=9005):
                'P6DT6H5M',
            datetime.timedelta(days=15):
                'P15D'
        }
        for timedelta, iso_duration in six.iteritems(EXPECTED):
            self.assertEqual(iso8601(timedelta), iso_duration)

    def test_is_ipv6(self):
        from axes.decorators import is_ipv6
        self.assertTrue(is_ipv6('ff80::220:16ff:fec9:1'))
        self.assertFalse(is_ipv6('67.255.125.204'))
        self.assertFalse(is_ipv6('foo'))

    @patch('axes.decorators.VERBOSE', True)
    def test_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.VERBOSE', False)
    def test_non_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = ip
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.VERBOSE', True)
    def test_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.AXES_ONLY_USER_FAILURES', True)
    @patch('axes.decorators.VERBOSE', False)
    def test_non_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = username
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.VERBOSE', True)
    def test_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.LOCK_OUT_BY_COMBINATION_USER_AND_IP', True)
    @patch('axes.decorators.VERBOSE', False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{0} from {1}'.format(username, ip)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.USE_USER_AGENT', True)
    @patch('axes.decorators.VERBOSE', True)
    def test_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @patch('axes.decorators.USE_USER_AGENT', True)
    @patch('axes.decorators.VERBOSE', False)
    def test_non_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = ip + '(user-agent={0})'.format(user_agent)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)


class GetIPProxyTest(TestCase):
    """Test get_ip returns correct addresses with proxy
    """
    def setUp(self):
        self.request = MockRequest()

    def test_iis_ipv4_port_stripping(self):
        self.ip = '192.168.1.1'

        valid_headers = [
            '192.168.1.1:6112',
            '192.168.1.1:6033, 192.168.1.2:9001',
        ]

        for header in valid_headers:
            self.request.META['HTTP_X_FORWARDED_FOR'] = header
            self.assertEqual(self.ip, get_ip(self.request))

    def test_valid_ipv4_parsing(self):
        self.ip = '192.168.1.1'

        valid_headers = [
            '192.168.1.1',
            '192.168.1.1, 192.168.1.2',
            ' 192.168.1.1  , 192.168.1.2  ',
            ' 192.168.1.1  , 2001:db8:cafe::17 ',
        ]

        for header in valid_headers:
            self.request.META['HTTP_X_FORWARDED_FOR'] = header
            self.assertEqual(self.ip, get_ip(self.request))

    def test_valid_ipv6_parsing(self):
        self.ip = '2001:db8:cafe::17'

        valid_headers = [
            '2001:db8:cafe::17',
            '2001:db8:cafe::17 , 2001:db8:cafe::18',
            '2001:db8:cafe::17,  2001:db8:cafe::18, 192.168.1.1',
        ]

        for header in valid_headers:
            self.request.META['HTTP_X_FORWARDED_FOR'] = header
            self.assertEqual(self.ip, get_ip(self.request))


class GetIPProxyCustomHeaderTest(TestCase):
    """Test that get_ip returns correct addresses with a custom proxy header
    """
    def setUp(self):
        self.request = MockRequest()

    def test_custom_header_parsing(self):
        self.ip = '2001:db8:cafe::17'

        valid_headers = [
            ' 2001:db8:cafe::17 , 2001:db8:cafe::18',
        ]

        for header in valid_headers:
            self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = header
            self.assertEqual(self.ip, get_ip(self.request))


class GetIPNumProxiesTest(TestCase):
    """Test that get_ip returns the correct last IP when NUM_PROXIES is configured
    """

    def setUp(self):
        self.request = MockRequest()

    def test_header_ordering(self):
        self.ip = '2.2.2.2'

        valid_headers = [
            '4.4.4.4, 3.3.3.3, 2.2.2.2, 1.1.1.1',
            '         3.3.3.3, 2.2.2.2, 1.1.1.1',
            '                  2.2.2.2, 1.1.1.1',
        ]

        for header in valid_headers:
            self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = header
            self.assertEqual(self.ip, get_ip(self.request))

    def test_invalid_headers_too_few(self):
        self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = '1.1.1.1'
        with self.assertRaises(Warning):
            get_ip(self.request)

    def test_invalid_headers_no_ip(self):
        self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = ''
        with self.assertRaises(Warning):
            get_ip(self.request)
