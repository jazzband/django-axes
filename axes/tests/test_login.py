"""
Integration tests for the login handling.

TODO: Clean up the tests in this module.
"""

from importlib import import_module

from django.http import HttpRequest
from django.test import override_settings, TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model, login, logout

from axes.conf import settings
from axes.models import AccessAttempt
from axes.tests.base import AxesTestCase


class DjangoLoginTestCase(TestCase):
    def setUp(self):
        engine = import_module(settings.SESSION_ENGINE)

        self.request = HttpRequest()
        self.request.session = engine.SessionStore()

        self.username = "john.doe"
        self.password = "hunter2"

        self.user = get_user_model().objects.create(username=self.username)
        self.user.set_password(self.password)
        self.user.save()
        self.user.backend = "django.contrib.auth.backends.ModelBackend"


class DjangoContribAuthLoginTestCase(DjangoLoginTestCase):
    def test_login(self):
        login(self.request, self.user)

    def test_logout(self):
        login(self.request, self.user)
        logout(self.request)


@override_settings(AXES_ENABLED=False)
class DjangoTestClientLoginTestCase(DjangoLoginTestCase):
    def test_client_login(self):
        self.client.login(username=self.username, password=self.password)

    def test_client_logout(self):
        self.client.login(username=self.username, password=self.password)
        self.client.logout()

    def test_client_force_login(self):
        self.client.force_login(self.user)


class LoginTestCase(AxesTestCase):
    """
    Test for lockouts under different configurations and circumstances to prevent false positives and false negatives.

    Always block attempted logins for the same user from the same IP.
    Always allow attempted logins for a different user from a different IP.
    """

    IP_1 = "10.1.1.1"
    IP_2 = "10.2.2.2"
    USER_1 = "valid-user-1"
    USER_2 = "valid-user-2"
    EMAIL_1 = "valid-email-1@example.com"
    EMAIL_2 = "valid-email-2@example.com"

    VALID_USERNAME = USER_1
    VALID_EMAIL = EMAIL_1
    VALID_PASSWORD = "valid-password"

    VALID_IP_ADDRESS = IP_1

    WRONG_PASSWORD = "wrong-password"
    LOCKED_MESSAGE = "Account locked: too many login attempts."
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'
    ALLOWED = 302
    BLOCKED = 403

    def _login(self, username, password, ip_addr="127.0.0.1", **kwargs):
        """
        Login a user and get the response.

        IP address can be configured to test IP blocking functionality.
        """

        post_data = {"username": username, "password": password}

        post_data.update(kwargs)

        return self.client.post(
            reverse("admin:login"),
            post_data,
            REMOTE_ADDR=ip_addr,
            HTTP_USER_AGENT="test-browser",
        )

    def _lockout_user_from_ip(self, username, ip_addr):
        for _ in range(settings.AXES_FAILURE_LIMIT):
            response = self._login(
                username=username, password=self.WRONG_PASSWORD, ip_addr=ip_addr
            )
        return response

    def _lockout_user1_from_ip1(self):
        return self._lockout_user_from_ip(username=self.USER_1, ip_addr=self.IP_1)

    def setUp(self):
        """
        Create two valid users for authentication.
        """

        super().setUp()

        self.user2 = get_user_model().objects.create_superuser(
            username=self.USER_2,
            email=self.EMAIL_2,
            password=self.VALID_PASSWORD,
            is_staff=True,
            is_superuser=True,
        )

    def test_login(self):
        """
        Test a valid login for a real username.
        """

        response = self._login(self.username, self.password)
        self.assertNotContains(
            response, self.LOGIN_FORM_KEY, status_code=self.ALLOWED, html=True
        )

    def test_lockout_limit_once(self):
        """
        Test the login lock trying to login one more time than failure limit.
        """

        response = self.lockout()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)

    def test_lockout_limit_many(self):
        """
        Test the login lock trying to login a lot of times more than failure limit.
        """

        self.lockout()

        for _ in range(settings.AXES_FAILURE_LIMIT):
            response = self.login()
            self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)

    @override_settings(AXES_RESET_ON_SUCCESS=False)
    def test_reset_on_success_false(self):
        self.almost_lockout()
        self.login(is_valid_username=True, is_valid_password=True)

        response = self.login()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)
        self.assertTrue(AccessAttempt.objects.count())

    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_reset_on_success_true(self):
        self.almost_lockout()
        self.assertTrue(AccessAttempt.objects.count())

        self.login(is_valid_username=True, is_valid_password=True)
        self.assertFalse(AccessAttempt.objects.count())

        response = self.lockout()
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)
        self.assertTrue(AccessAttempt.objects.count())

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_combination_user_and_ip(self):
        """
        Test login failure when AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP is True.
        """

        # test until one try before the limit
        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self.login(is_valid_username=True, is_valid_password=False)
            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self.login(is_valid_username=True, is_valid_password=False)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=403)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_only_user_failures(self):
        """
        Test login failure when AXES_ONLY_USER_FAILURES is True.
        """

        # test until one try before the limit
        for _ in range(1, settings.AXES_FAILURE_LIMIT):
            response = self._login(self.username, self.WRONG_PASSWORD)

            # Check if we are in the same login page
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(self.username, self.WRONG_PASSWORD)
        self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)

        # reset the username only and make sure we can log in now even though our IP has failed each time
        self.reset(username=self.username)

        response = self._login(self.username, self.password)

        # Check if we are still in the login page
        self.assertNotContains(
            response, self.LOGIN_FORM_KEY, status_code=self.ALLOWED, html=True
        )

        # now create failure_limit + 1 failed logins and then we should still
        # be able to login with valid_username
        for _ in range(settings.AXES_FAILURE_LIMIT):
            response = self._login(self.username, self.password)

        # Check if we can still log in with valid user
        response = self._login(self.username, self.password)
        self.assertNotContains(
            response, self.LOGIN_FORM_KEY, status_code=self.ALLOWED, html=True
        )

    # Test for true and false positives when blocking by IP *OR* user (default)
    # Cache disabled. Default settings.
    def test_lockout_by_ip_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    def test_lockout_by_ip_blocks_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_diff_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user only.
    # Cache disabled. When AXES_ONLY_USER_FAILURES = True
    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_with_empty_username_allows_other_users_without_cache(self):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username="", ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse("admin:login"), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200, html=True)

    # Test for true and false positives when blocking by user and IP together.
    # Cache disabled. When LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_without_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_with_empty_username_allows_other_users_without_cache(
        self,
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username="", ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse("admin:login"), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200, html=True)

    # Test for true and false positives when blocking by IP *OR* user (default)
    # With cache enabled. Default criteria.
    def test_lockout_by_ip_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    def test_lockout_by_ip_blocks_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 is also locked out from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    def test_lockout_by_ip_allows_when_diff_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_with_empty_username_allows_other_users_using_cache(self):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username="", ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse("admin:login"), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200, html=True)

    # Test for true and false positives when blocking by user only.
    # With cache enabled. When AXES_ONLY_USER_FAILURES = True
    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_blocks_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is also locked out from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_lockout_by_user_allows_when_diff_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    # Test for true and false positives when blocking by user and IP together.
    # With cache enabled. When LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_blocks_when_same_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 is still blocked from IP 1.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.BLOCKED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_same_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 1 can still login from IP 2.
        response = self._login(self.USER_1, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_same_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 1.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_1)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_allows_when_diff_user_diff_ip_using_cache(self):
        # User 1 is locked out from IP 1.
        self._lockout_user1_from_ip1()

        # User 2 can still login from IP 2.
        response = self._login(self.USER_2, self.VALID_PASSWORD, ip_addr=self.IP_2)
        self.assertEqual(response.status_code, self.ALLOWED)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    def test_lockout_by_user_and_ip_with_empty_username_allows_other_users_using_cache(
        self,
    ):
        # User with empty username is locked out from IP 1.
        self._lockout_user_from_ip(username="", ip_addr=self.IP_1)

        # Still possible to access the login page
        response = self.client.get(reverse("admin:login"), REMOTE_ADDR=self.IP_1)
        self.assertContains(response, self.LOGIN_FORM_KEY, status_code=200, html=True)
