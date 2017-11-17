import json

from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth.models import User

from axes.conf import settings


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
            reverse('admin:login'), post_data, REMOTE_ADDR=ip_addr, **headers
        )
        return response

    def _lockout_user_from_ip(self, username, ip_addr):
        for i in range(1, settings.AXES_FAILURE_LIMIT + 1):
            response = self._login(
                username=username,
                password=self.WRONG_PASSWORD,
                ip_addr=ip_addr,
            )
        return response

    def _lockout_user1_from_ip1(self):
        return self._lockout_user_from_ip(
            username=self.USER_1,
            ip_addr=self.IP_1,
        )

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

    # Test for true and false positives when blocking by IP *OR* user (default)
    # Cache disabled. Default settings.
    def test_lockout_by_ip_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    def test_lockout_by_ip_blocks_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_diff_user_diff_ip_without_cache(self):
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
    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_with_empty_username_allows_other_users_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username='', ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse('admin:login'), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200)

    # Test for true and false positives when blocking by user and IP together.
    # Cache disabled. When LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_with_empty_username_allows_other_users_without_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username='', ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse('admin:login'), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200)

    # Test for true and false positives when blocking by IP *OR* user (default)
    # With cache enabled. Default criteria.
    def test_lockout_by_ip_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    def test_lockout_by_ip_blocks_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_diff_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_with_empty_username_allows_other_users_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username='', ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse('admin:login'), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200)

    # Test for true and false positives when blocking by user only.
    # With cache enabled. When AXES_ONLY_USER_FAILURES = True
    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_using_cache(self):
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
    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(
            self.USER_1,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_1
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(
            self.USER_2,
            self.VALID_PASSWORD,
            ip_addr=self.IP_2
        )
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_with_empty_username_allows_other_users_using_cache(
        self, cache_get_mock=None, cache_set_mock=None
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username='', ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse('admin:login'), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200)
