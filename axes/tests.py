import random
import string
import time
import json
import datetime

from mock import patch

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings
from django.contrib.auth.models import User
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse
from django.utils import six

from axes.decorators import get_ip
from axes.settings import COOLOFF_TIME
from axes.settings import FAILURE_LIMIT
from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
from axes.utils import reset, iso8601


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

    def test_failure_limit_once(self):
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
    def test_lockout_by_combination_user_and_ip(self):
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

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_only(self):
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

    def test_log_data_truncated(self):
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
    def test_non_valid_login_without_success_log(self):
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
    def test_non_valid_login_without_log(self):
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
