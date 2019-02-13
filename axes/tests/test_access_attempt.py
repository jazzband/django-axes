import datetime
import hashlib
import random
import string
import time
from unittest.mock import patch, MagicMock

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from django.urls import reverse

from axes.attempts import (
    get_cache_key,
    get_cache_timeout,
    is_already_locked,
    ip_in_blacklist,
    ip_in_whitelist,
    is_user_lockable,
    get_filter_kwargs,
    get_user_attempts,
)
from axes.conf import settings
from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
from axes.utils import reset


@override_settings(AXES_COOLOFF_TIME=datetime.timedelta(seconds=2))
class AccessAttemptTest(TestCase):
    """
    Test case using custom settings for testing.
    """

    VALID_USERNAME = 'valid-username'
    VALID_PASSWORD = 'valid-password'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'

    def _login(self, is_valid_username=False, is_valid_password=False, **kwargs):
        """
        Login a user.

        A valid credential is used when is_valid_username is True,
        otherwise it will use a random string to make a failed login.
        """

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

        return self.client.post(
            reverse('admin:login'),
            post_data,
            **headers
        )

    def setUp(self):
        """
        Create a valid user for login.
        """

        self.username = self.VALID_USERNAME
        self.ip_address = '127.0.0.1'
        self.user_agent = 'test-browser'

        self.user = User.objects.create_superuser(
            username=self.VALID_USERNAME,
            email='test@example.com',
            password=self.VALID_PASSWORD,
        )

    def test_failure_limit_once(self):
        """
        Test the login lock trying to login one more time than failure limit.
        """

        # test until one try before the limit
        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_failure_limit_many(self):
        """
        Test the login lock trying to login a lot of times more than failure limit.
        """

        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # We should get a locked message each time we try again
        for _ in range(random.randrange(1, settings.AXES_FAILURE_LIMIT)):
            response = self._login()
            self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_valid_login(self):
        """
        Test a valid login for a real username.
        """

        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

    def test_valid_logout(self):
        """
        Test a valid logout and make sure the logout_time is updated.
        """

        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertEqual(AccessLog.objects.latest('id').logout_time, None)

        response = self.client.get(reverse('admin:logout'))
        self.assertNotEqual(AccessLog.objects.latest('id').logout_time, None)
        self.assertContains(response, 'Logged out')

    def test_cooling_off(self):
        """
        Test if the cooling time allows a user to login.
        """

        self.test_failure_limit_once()

        # Wait for the cooling off period
        time.sleep(settings.AXES_COOLOFF_TIME.total_seconds())

        # It should be possible to login again, make sure it is.
        self.test_valid_login()

    def test_cooling_off_for_trusted_user(self):
        """
        Test the cooling time for a trusted user.
        """

        # Test successful login-logout, this makes the user trusted.
        self.test_valid_logout()

        # Try the cooling off time
        self.test_cooling_off()

    def test_long_user_agent_valid(self):
        """
        Test if can handle a long user agent.
        """

        long_user_agent = 'ie6' * 1024
        response = self._login(
            is_valid_username=True,
            is_valid_password=True,
            user_agent=long_user_agent,
        )
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

    def test_long_user_agent_not_valid(self):
        """
        Test if can handle a long user agent with failure.
        """

        long_user_agent = 'ie6' * 1024
        for _ in range(settings.AXES_FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    def test_reset_ip(self):
        """
        Test resetting all attempts for an IP address.
        """

        # Make a lockout
        self.test_failure_limit_once()

        # Reset the ip so we can try again
        reset(ip='127.0.0.1')

        # Make a login attempt again
        self.test_valid_login()

    def test_reset_all(self):
        """
        Test resetting all attempts.
        """

        # Make a lockout
        self.test_failure_limit_once()

        # Reset all attempts so we can try again
        reset()

        # Make a login attempt again
        self.test_valid_login()

    @override_settings(
        AXES_ONLY_USER_FAILURES=True,
    )
    def test_get_filter_kwargs_user(self):
        self.assertEqual(
            dict(get_filter_kwargs(self.username, self.ip_address, self.user_agent)),
            {'username': self.username},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=False,
        AXES_USE_USER_AGENT=False,
    )
    def test_get_filter_kwargs_ip(self):
        self.assertEqual(
            dict(get_filter_kwargs(self.username, self.ip_address, self.user_agent)),
            {'ip_address': self.ip_address},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True,
        AXES_USE_USER_AGENT=False,
    )
    def test_get_filter_kwargs_user_and_ip(self):
        self.assertEqual(
            dict(get_filter_kwargs(self.username, self.ip_address, self.user_agent)),
            {'username': self.username, 'ip_address': self.ip_address},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=False,
        AXES_USE_USER_AGENT=True,
    )
    def test_get_filter_kwargs_ip_and_agent(self):
        self.assertEqual(
            dict(get_filter_kwargs(self.username, self.ip_address, self.user_agent)),
            {'ip_address': self.ip_address, 'user_agent': self.user_agent},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True,
        AXES_USE_USER_AGENT=True,
    )
    def test_get_filter_kwargs_user_ip_agent(self):
        self.assertEqual(
            dict(get_filter_kwargs(self.username, self.ip_address, self.user_agent)),
            {'username': self.username, 'ip_address': self.ip_address, 'user_agent': self.user_agent},
        )

    @patch('axes.attempts.get_axes_cache')
    def test_get_user_attempts_updates_cache(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 1
        cache.set.return_value = None
        get_cache.return_value = cache

        attempt = AccessAttempt.objects.create(
            username=self.username,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            failures_since_start=0,
        )

        request = HttpRequest()
        request.META['REMOTE_ADDR'] = self.ip_address
        request.META['HTTP_USER_AGENT'] = self.user_agent
        credentials = {'username': self.username}

        # Check that the function does nothing if cool off has not passed
        cache.get.assert_not_called()
        cache.set.assert_not_called()

        self.assertEqual(
            list(get_user_attempts(request, credentials)),
            [attempt],
        )

        cache.get.assert_not_called()
        cache.set.assert_not_called()

        time.sleep(settings.AXES_COOLOFF_TIME.seconds)

        self.assertEqual(
            list(get_user_attempts(request, credentials)),
            [],
        )

        self.assertTrue(cache.get.call_count)
        self.assertTrue(cache.set.call_count)

    @patch('axes.utils.get_client_ip', return_value='127.0.0.1')
    def test_get_cache_key(self, _):
        """
        Test the cache key format.
        """

        # Getting cache key from request
        ip_address = '127.0.0.1'
        cache_hash_key = 'axes-{}'.format(
            hashlib.md5(ip_address.encode()).hexdigest()
        )

        request_factory = RequestFactory()
        request = request_factory.post(
            '/admin/login/',
            data={
                'username': self.VALID_USERNAME,
                'password': 'test',
            },
        )

        self.assertEqual(cache_hash_key, get_cache_key(request))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent='<unknown>',
            ip_address=ip_address,
            username=self.VALID_USERNAME,
            get_data='',
            post_data='',
            http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
            path_info=request.META.get('PATH_INFO', '<unknown>'),
            failures_since_start=0,
        )

        self.assertEqual(cache_hash_key, get_cache_key(attempt))

    @patch('axes.utils.get_client_ip', return_value='127.0.0.1')
    def test_get_cache_key_credentials(self, _):
        """
        Test the cache key format.
        """

        # Getting cache key from request
        ip_address = '127.0.0.1'
        cache_hash_key = 'axes-{}'.format(
            hashlib.md5(ip_address.encode()).hexdigest()
        )

        request_factory = RequestFactory()
        request = request_factory.post('/admin/login/',
                                       data={
                                           'username': self.VALID_USERNAME,
                                           'password': 'test'
                                       })

        # Difference between the upper test: new call signature with credentials
        credentials = {'username': self.VALID_USERNAME}

        self.assertEqual(cache_hash_key, get_cache_key(request, credentials))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent='<unknown>',
            ip_address=ip_address,
            username=self.VALID_USERNAME,
            get_data='',
            post_data='',
            http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
            path_info=request.META.get('PATH_INFO', '<unknown>'),
            failures_since_start=0,
        )
        self.assertEqual(cache_hash_key, get_cache_key(attempt))

    def test_send_lockout_signal(self):
        """
        Test if the lockout signal is emitted.
        """

        # this "hack" is needed so we don't have to use global variables or python3 features
        class Scope(object): pass
        scope = Scope()
        scope.signal_received = 0

        def signal_handler(request, username, ip_address, *args, **kwargs):  # pylint: disable=unused-argument
            scope.signal_received += 1
            self.assertIsNotNone(request)

        # Connect signal handler
        user_locked_out.connect(signal_handler)

        # Make a lockout
        self.test_failure_limit_once()
        self.assertEqual(scope.signal_received, 1)

        reset()

        # Make another lockout
        self.test_failure_limit_once()
        self.assertEqual(scope.signal_received, 2)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_combination_user_and_ip(self):
        """
        Test login failure when AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True.
        """

        # test until one try before the limit
        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self._login(
                is_valid_username=True,
                is_valid_password=False,
            )
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_only(self):
        """
        Test login failure when AXES_ONLY_USER_FAILURES is True.
        """

        # test until one try before the limit
        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self._login(
                is_valid_username=True,
                is_valid_password=False,
            )
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

        # reset the username only and make sure we can log in now even though
        # our IP has failed each time
        reset(username=AccessAttemptTest.VALID_USERNAME)
        response = self._login(
            is_valid_username=True,
            is_valid_password=True,
        )
        # Check if we are still in the login page
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

        # now create failure_limit + 1 failed logins and then we should still
        # be able to login with valid_username
        for _ in range(settings.AXES_FAILURE_LIMIT):
            response = self._login(
                is_valid_username=False,
                is_valid_password=False,
            )
        # Check if we can still log in with valid user
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

    def test_log_data_truncated(self):
        """
        Test that query2str properly truncates data to the max_length (default 1024).
        """

        # An impossibly large post dict
        extra_data = {string.ascii_letters * x: x for x in range(0, 1000)}
        self._login(**extra_data)
        self.assertEqual(
            len(AccessAttempt.objects.latest('id').post_data), 1024
        )

    @override_settings(AXES_DISABLE_SUCCESS_ACCESS_LOG=True)
    def test_valid_logout_without_success_log(self):
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)
        response = self.client.get(reverse('admin:logout'))

        self.assertEqual(AccessLog.objects.all().count(), 0)
        self.assertContains(response, 'Logged out', html=True)

    @override_settings(AXES_DISABLE_SUCCESS_ACCESS_LOG=True)
    def test_valid_login_without_success_log(self):
        """
        Test that a valid login does not generate an AccessLog when DISABLE_SUCCESS_ACCESS_LOG is True.
        """

        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccessLog.objects.all().count(), 0)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_log(self):
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=True)
        response = self.client.get(reverse('admin:logout'))

        self.assertEqual(AccessLog.objects.first().logout_time, None)
        self.assertContains(response, 'Logged out', html=True)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_non_valid_login_without_log(self):
        """
        Test that a non-valid login does generate an AccessLog when DISABLE_ACCESS_LOG is True.
        """
        AccessLog.objects.all().delete()

        response = self._login(is_valid_username=True, is_valid_password=False)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(AccessLog.objects.all().count(), 0)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_check_is_not_made_on_GET(self):
        AccessLog.objects.all().delete()

        response = self.client.get(reverse('admin:login'))
        self.assertEqual(response.status_code, 200)

        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertEqual(response.status_code, 302)

        response = self.client.get(reverse('admin:index'))
        self.assertEqual(response.status_code, 200)

    def test_custom_authentication_backend(self):
        """
        Test that log_user_login_failed skips if an attempt to authenticate with a custom authentication backend fails.
        """

        request = HttpRequest()
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        authenticate(request=request, foo='bar')
        self.assertEqual(AccessLog.objects.all().count(), 0)

    def _assert_resets_on_success(self):
        """
        Sets the AXES_RESET_ON_SUCCESS up for testing.
        """

        # test until one try before the limit
        for _ in range(settings.AXES_FAILURE_LIMIT - 1):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # Perform a valid login
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

        return self._login()

    # by default, AXES_RESET_ON_SUCCESS = False
    def test_reset_on_success_default(self):
        """
        Test that the failure attempts does not reset after one successful attempt by default.
        """

        response = self._assert_resets_on_success()

        # So, we shouldn't have found a lock-out yet.
        # But we should find one now
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_reset_on_success(self):
        """
        Test that the failure attempts resets after one successful attempt when using the corresponding setting.
        """

        response = self._assert_resets_on_success()

        # So, we shouldn't have found a lock-out yet.
        # And we shouldn't find one now
        self.assertContains(response, self.LOGIN_FORM_KEY, html=True)
        for _ in range(settings.AXES_FAILURE_LIMIT - 2):
            response = self._login()
            # Check if we are on the same login page.
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # But we should find one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)


class AttemptUtilsTestCase(TestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = 'POST'
        self.request.META['REMOTE_ADDR'] = '127.0.0.1'

    @override_settings(AXES_IP_WHITELIST=None)
    def test_ip_in_whitelist_none(self):
        self.assertFalse(ip_in_whitelist('127.0.0.2'))

    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_ip_in_whitelist(self):
        self.assertTrue(ip_in_whitelist('127.0.0.1'))
        self.assertFalse(ip_in_whitelist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=None)
    def test_ip_in_blacklist_none(self):
        self.assertFalse(ip_in_blacklist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.1'])
    def test_ip_in_blacklist(self):
        self.assertTrue(ip_in_blacklist('127.0.0.1'))
        self.assertFalse(ip_in_blacklist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.1'])
    def test_is_already_locked_ip_in_blacklist(self):
        self.assertTrue(is_already_locked(self.request))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.2'])
    def test_is_already_locked_ip_not_in_blacklist(self):
        self.assertFalse(is_already_locked(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_is_already_locked_ip_in_whitelist(self):
        self.assertFalse(is_already_locked(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.2'])
    def test_is_already_locked_ip_not_in_whitelist(self):
        self.assertTrue(is_already_locked(self.request))

    @override_settings(AXES_COOLOFF_TIME=3)  # hours
    def test_get_cache_timeout(self):
        timeout_seconds = float(60 * 60 * 3)
        self.assertEqual(get_cache_timeout(), timeout_seconds)

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=True)
    @override_settings(AXES_FAILURE_LIMIT=40)
    @patch('axes.attempts.get_axes_cache')
    def test_is_already_locked_cache(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 42
        get_cache.return_value = cache

        self.assertTrue(is_already_locked(self.request, {}))
        self.assertTrue(cache.get.call_count)

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    @override_settings(AXES_FAILURE_LIMIT=40)
    @patch('axes.attempts.get_axes_cache')
    def test_is_already_locked_do_not_lock_out_at_failure(self, get_cache):
        cache = MagicMock()
        cache.get.return_value = 42
        get_cache.return_value = cache

        self.assertFalse(is_already_locked(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_already_locked_never_lockout_get(self):
        request = HttpRequest()
        request.method = 'GET'
        self.assertFalse(is_already_locked(request))

    def test_is_already_locked_nolockable(self):
        UserModel = get_user_model()
        user = UserModel.objects.create(username='jane.doe')

        with self.subTest('User is marked as nolockout.'):
            with patch.object(UserModel, 'nolockout', True, create=True):
                locked = is_already_locked(self.request, {UserModel.USERNAME_FIELD: user.username})
                self.assertFalse(locked)

    def test_is_user_lockable(self):
        UserModel = get_user_model()
        user = UserModel.objects.create(username='jane.doe')

        with self.subTest('User is marked as nolockout.'):
            with patch.object(UserModel, 'nolockout', True, create=True):
                lockable = is_user_lockable(self.request, {UserModel.USERNAME_FIELD: user.username})
                self.assertFalse(lockable)

        with self.subTest('User exists but attemptee can be locked out.'):
            lockable = is_user_lockable(self.request, {UserModel.USERNAME_FIELD: user.username})
            self.assertTrue(lockable)

        with self.subTest('User does not exist and attemptee can be locked out.'):
            lockable = is_user_lockable(self.request, {UserModel.USERNAME_FIELD: 'not.' + user.username})
            self.assertTrue(lockable)
