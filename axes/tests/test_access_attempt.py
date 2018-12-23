from __future__ import unicode_literals

import datetime
import hashlib
import json
import random
import string
import time

from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.test.client import RequestFactory

from axes.conf import settings
from axes.attempts import get_cache_key
from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
from axes.tests.compatibility import patch
from axes.utils import reset


@override_settings(AXES_COOLOFF_TIME=datetime.timedelta(seconds=2))
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

        response = self.client.post(
            reverse('admin:login'), post_data, **headers
        )

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
        """Tests the login lock trying to login a lot of times more
        than failure limit
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
        """Tests a valid login for a real username
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

    def test_valid_logout(self):
        """Tests a valid logout and make sure the logout_time is updated
        """
        response = self._login(is_valid_username=True, is_valid_password=True)
        self.assertEqual(AccessLog.objects.latest('id').logout_time, None)

        response = self.client.get(reverse('admin:logout'))
        self.assertNotEqual(AccessLog.objects.latest('id').logout_time, None)
        self.assertContains(response, 'Logged out')

    def test_cooling_off(self):
        """Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_once()

        # Wait for the cooling off period
        time.sleep(settings.AXES_COOLOFF_TIME.total_seconds())

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
        response = self._login(
            is_valid_username=True,
            is_valid_password=True,
            user_agent=long_user_agent,
        )
        self.assertNotContains(response, self.LOGIN_FORM_KEY, status_code=302, html=True)

    def test_long_user_agent_not_valid(self):
        """Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for _ in range(settings.AXES_FAILURE_LIMIT + 1):
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

    @patch('axes.utils.get_client_ip', return_value='127.0.0.1')
    def test_get_cache_key(self, _):
        """ Test the cache key format"""
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
        """ Test the cache key format"""
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
        """Test if the lockout signal is emitted
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
        """Tests the login lock with a valid username and invalid password
        when AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True
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
        """Tests the login lock with a valid username and invalid password
        when AXES_ONLY_USER_FAILURES is True
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
        """Tests that query2str properly truncates data to the
        max_length (default 1024)
        """
        # An impossibly large post dict
        extra_data = {string.ascii_letters * x: x for x in range(0, 1000)}
        self._login(**extra_data)
        self.assertEqual(
            len(AccessAttempt.objects.latest('id').post_data), 1024
        )

    def test_json_response(self):
        """Tests response content type and status code for the ajax request
        """
        self.test_failure_limit_once()
        response = self._login(is_json=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get('Content-Type'), 'application/json')

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
        A valid login doesn't generate an AccessLog when
        `DISABLE_SUCCESS_ACCESS_LOG=True`.
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
        A non-valid login does generate an AccessLog when
        `DISABLE_ACCESS_LOG=True`.
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
        '''
        ``log_user_login_failed`` should shortcircuit if an attempt to authenticate
        with a custom authentication backend fails.
        '''

        request = HttpRequest()
        request.user = self.user
        authenticate(request=request, foo='bar')
        self.assertEqual(AccessLog.objects.all().count(), 0)

    def _assert_resets_on_success(self):
        """Sets up for testing the AXES_RESET_ON_SUCCESS setting.
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
        """Tests that the failure attempts does not reset after one successful
        attempt by default.
        """
        response = self._assert_resets_on_success()

        # So, we shouldn't have found a lock-out yet.
        # But we should find one now
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_reset_on_success(self):
        """Tests that the failure attempts resets after one successful
        attempt when using the corresponding setting.
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
