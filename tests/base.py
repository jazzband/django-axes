from random import choice
from string import ascii_letters, digits
from time import sleep

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now

from axes.conf import settings
from axes.helpers import (
    get_cache,
    get_client_http_accept,
    get_client_ip_address,
    get_client_path_info,
    get_client_user_agent,
    get_cool_off,
    get_credentials,
    get_failure_limit,
)
from axes.models import AccessAttempt, AccessLog
from axes.utils import reset


def custom_failure_limit(request, credentials):
    return 3


class AxesTestCase(TestCase):
    """
    Test case using custom settings for testing.
    """

    VALID_USERNAME = "axes-valid-username"
    VALID_PASSWORD = "axes-valid-password"
    VALID_EMAIL = "axes-valid-email@example.com"
    VALID_USER_AGENT = "axes-user-agent"
    VALID_IP_ADDRESS = "127.0.0.1"

    INVALID_USERNAME = "axes-invalid-username"
    INVALID_PASSWORD = "axes-invalid-password"
    INVALID_EMAIL = "axes-invalid-email@example.com"

    LOCKED_MESSAGE = "Account locked: too many login attempts."
    LOGOUT_MESSAGE = "Logged out"
    LOGIN_FORM_KEY = '<input type="submit" value="Log in" />'

    STATUS_SUCCESS = 200
    ALLOWED = 302
    BLOCKED = 403

    def setUp(self):
        """
        Create a valid user for login.
        """

        self.username = self.VALID_USERNAME
        self.password = self.VALID_PASSWORD
        self.email = self.VALID_EMAIL

        self.ip_address = self.VALID_IP_ADDRESS
        self.user_agent = self.VALID_USER_AGENT
        self.path_info = reverse("admin:login")

        self.user = get_user_model().objects.create_superuser(
            username=self.username, password=self.password, email=self.email
        )

        self.request = HttpRequest()
        self.request.method = "POST"
        self.request.META["REMOTE_ADDR"] = self.ip_address
        self.request.META["HTTP_USER_AGENT"] = self.user_agent
        self.request.META["PATH_INFO"] = self.path_info

        self.request.axes_attempt_time = now()
        self.request.axes_ip_address = get_client_ip_address(self.request)
        self.request.axes_user_agent = get_client_user_agent(self.request)
        self.request.axes_path_info = get_client_path_info(self.request)
        self.request.axes_http_accept = get_client_http_accept(self.request)
        self.request.axes_failures_since_start = None

        self.credentials = get_credentials(self.username)

    def tearDown(self):
        get_cache().clear()

    def get_kwargs_with_defaults(self, **kwargs):
        defaults = {
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "username": self.username,
        }

        defaults.update(kwargs)
        return defaults

    def create_attempt(self, **kwargs):
        kwargs = self.get_kwargs_with_defaults(**kwargs)
        kwargs.setdefault("failures_since_start", 1)
        return AccessAttempt.objects.create(**kwargs)

    def create_log(self, **kwargs):
        return AccessLog.objects.create(**self.get_kwargs_with_defaults(**kwargs))

    def reset(self, ip=None, username=None):
        return reset(ip, username)

    def login(
        self,
        is_valid_username=False,
        is_valid_password=False,
        remote_addr=None,
        **kwargs
    ):
        """
        Login a user.

        A valid credential is used when is_valid_username is True,
        otherwise it will use a random string to make a failed login.
        """

        if is_valid_username:
            username = self.VALID_USERNAME
        else:
            username = "".join(choice(ascii_letters + digits) for _ in range(10))

        if is_valid_password:
            password = self.VALID_PASSWORD
        else:
            password = self.INVALID_PASSWORD

        post_data = {"username": username, "password": password, **kwargs}

        return self.client.post(
            reverse("admin:login"),
            post_data,
            REMOTE_ADDR=remote_addr or self.ip_address,
            HTTP_USER_AGENT=self.user_agent,
        )

    def logout(self):
        return self.client.post(
            reverse("admin:logout"),
            REMOTE_ADDR=self.ip_address,
            HTTP_USER_AGENT=self.user_agent,
        )

    def check_login(self):
        response = self.login(is_valid_username=True, is_valid_password=True)
        self.assertNotContains(
            response, self.LOGIN_FORM_KEY, status_code=self.ALLOWED, html=True
        )

    def almost_lockout(self):
        for _ in range(1, get_failure_limit(None, None)):
            response = self.login()
            self.assertContains(response, self.LOGIN_FORM_KEY, html=True)

    def lockout(self):
        self.almost_lockout()
        return self.login()

    def check_lockout(self):
        response = self.lockout()
        if settings.AXES_LOCK_OUT_AT_FAILURE == True:
            self.assertContains(response, self.LOCKED_MESSAGE, status_code=self.BLOCKED)
        else:
            self.assertNotContains(
                response, self.LOCKED_MESSAGE, status_code=self.STATUS_SUCCESS
            )

    def cool_off(self):
        sleep(get_cool_off().total_seconds())

    def check_logout(self):
        response = self.logout()
        self.assertContains(
            response, self.LOGOUT_MESSAGE, status_code=self.STATUS_SUCCESS
        )

    def check_handler(self):
        """
        Check a handler and its basic functionality with lockouts, cool offs, login, and logout.

        This is a check that is intended to successfully run for each and every new handler.
        """

        self.check_lockout()
        self.cool_off()
        self.check_login()
        self.check_logout()
