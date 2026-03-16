from datetime import timedelta
from hashlib import sha256
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.test import RequestFactory, override_settings

from axes.apps import AppConfig
from axes.helpers import (
    cleanse_parameters,
    get_cache_timeout,
    get_client_cache_keys,
    get_client_ip_address,
    get_client_parameters,
    get_client_str,
    get_client_username,
    get_cool_off,
    get_cool_off_iso8601,
    get_lockout_response,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
    is_ip_address_in_blacklist,
    is_ip_address_in_whitelist,
    is_user_attempt_whitelisted,
    toggleable,
)
from axes.models import AccessAttempt
from tests.base import AxesTestCase


@override_settings(AXES_ENABLED=False)
class AxesDisabledTestCase(AxesTestCase):
    def test_initialize(self):
        AppConfig.logging_initialized = False
        AppConfig.initialize()
        self.assertFalse(AppConfig.logging_initialized)

    def test_toggleable(self):
        def is_true():
            return True

        self.assertTrue(is_true())
        self.assertIsNone(toggleable(is_true)())


class CacheTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=3)  # hours
    def test_get_cache_timeout_integer(self):
        timeout_seconds = float(60 * 60 * 3)
        self.assertEqual(get_cache_timeout(), timeout_seconds)

    @override_settings(AXES_COOLOFF_TIME=timedelta(seconds=420))
    def test_get_cache_timeout_timedelta(self):
        self.assertEqual(get_cache_timeout(), 420)

    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cache_timeout_none(self):
        self.assertEqual(get_cache_timeout(), None)

    def test_get_increasing_cache_timeout_by_username(self):
        user_durations = {
            "ben": timedelta(minutes=5),
            "jen": timedelta(minutes=10),
        }

        def _callback(request):
            username = request.POST["username"] if request else object()
            previous_duration = user_durations.get(username, timedelta())
            user_durations[username] = previous_duration + timedelta(minutes=5)
            return user_durations[username]

        rf = RequestFactory()
        ben_req = rf.post("/", data={"username": "ben"})
        jen_req = rf.post("/", data={"username": "jen"})
        james_req = rf.post("/", data={"username": "james"})

        with override_settings(AXES_COOLOFF_TIME=_callback):
            with self.subTest("no username"):
                self.assertEqual(get_cache_timeout(), 300)

            with self.subTest("ben"):
                self.assertEqual(get_cache_timeout(ben_req), 600)
                self.assertEqual(get_cache_timeout(ben_req), 900)
                self.assertEqual(get_cache_timeout(ben_req), 1200)

            with self.subTest("jen"):
                self.assertEqual(get_cache_timeout(jen_req), 900)

            with self.subTest("james"):
                self.assertEqual(get_cache_timeout(james_req), 300)


class TimestampTestCase(AxesTestCase):
    def test_iso8601(self):
        """
        Test get_cool_off_iso8601 correctly translates datetime.timedelta to ISO 8601 formatted duration.
        """

        expected = {
            timedelta(days=1, hours=25, minutes=42, seconds=8): "P2DT1H42M8S",
            timedelta(days=7, seconds=342): "P7DT5M42S",
            timedelta(days=0, hours=2, minutes=42): "PT2H42M",
            timedelta(hours=20, seconds=42): "PT20H42S",
            timedelta(seconds=300): "PT5M",
            timedelta(seconds=9005): "PT2H30M5S",
            timedelta(minutes=9005): "P6DT6H5M",
            timedelta(days=15): "P15D",
        }

        for delta, iso_duration in expected.items():
            with self.subTest(iso_duration):
                self.assertEqual(get_cool_off_iso8601(delta), iso_duration)


@override_settings(AXES_SENSITIVE_PARAMETERS=[])
class ClientStringTestCase(AxesTestCase):
    @staticmethod
    def get_expected_client_str(*args, **kwargs):
        client_str_template = '{{username: "{0}", ip_address: "{1}", user_agent: "{2}", path_info: "{3}"}}'
        return client_str_template.format(*args, **kwargs)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_imbalanced_quotes(self):
        username = "butterfly.. },,,"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details_tuple(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = ("admin", "login")

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info[0], self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_ip_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", user_agent: "Googlebot/2.1 (+http://www.googlebot.com/bot.html)", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(
        AXES_CLIENT_STR_CALLABLE="tests.test_helpers.get_dummy_client_str"
    )
    def test_get_client_str_callable_return_str(self):
        self.assertEqual(
            get_client_str(
                "username", "ip_address", "user_agent", "path_info", self.request
            ),
            "client string",
        )

    @override_settings(
        AXES_CLIENT_STR_CALLABLE="tests.test_helpers.get_dummy_client_str_using_request"
    )
    def test_get_client_str_callable_using_request(self):
        self.request.user = self.user
        self.assertEqual(
            get_client_str(
                "username", "ip_address", "user_agent", "path_info", self.request
            ),
            self.email,
        )

    @override_settings(AXES_SENSITIVE_PARAMETERS=["username"])
    def test_get_client_str_with_sensitive_parameters(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            "********************",
            ip_address,
            user_agent,
            path_info,
            self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)


def get_dummy_client_str(username, ip_address, user_agent, path_info, request):
    return "client string"


def get_dummy_client_str_using_request(
    username, ip_address, user_agent, path_info, request
):
    return f"{request.user.email}"


def get_dummy_lockout_parameters(request, credentials=None):
    return ["ip_address", ["username", "user_agent"]]


class ClientParametersTestCase(AxesTestCase):
    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_get_filter_kwargs_user(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}],
        )

    def test_get_filter_kwargs_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_get_filter_kwargs_user_and_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username, "ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "user_agent"]])
    def test_get_filter_kwargs_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["ip_address", ["username", "user_agent"]])
    def test_get_filter_kwargs_ip_or_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address}, {"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"], ["username", "user_agent"]])
    def test_get_filter_kwargs_ip_and_user_agent_or_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address, "user_agent": self.user_agent}, {"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_get_filter_kwargs_user_or_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}, {"ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address", "user_agent"])
    def test_get_filter_kwargs_user_or_ip_or_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}, {"ip_address": self.ip_address}, {"user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    def test_get_filter_kwargs_ip_and_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address, "user_agent": self.user_agent}],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=[["username", "ip_address", "user_agent"]]
    )
    def test_get_filter_kwargs_user_ip_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [
                {
                    "username": self.username,
                    "ip_address": self.ip_address,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["wrong_param"])
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_invalid_parameter(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "wrong_param"]])
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_invalid_combined_parameter(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=get_dummy_lockout_parameters)
    def test_get_filter_kwargs_callable_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "ip_address": self.ip_address,
                },
                {
                    "username": self.username,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS="tests.test_helpers.get_dummy_lockout_parameters"
    )
    def test_get_filter_kwargs_callable_str_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "ip_address": self.ip_address,
                },
                {
                    "username": self.username,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: ["username"]
    )
    def test_get_filter_kwargs_callable_lambda_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "username": self.username,
                },
            ],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=True)
    def test_get_filter_kwargs_not_list_or_callable(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=lambda: None)
    def test_get_filter_kwargs_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=lambda request, credentials, extra: None)
    def test_get_filter_kwargs_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: ["wrong_param"]
    )
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_callable_invalid_lockout_param(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: [
            ["ip_address", "wrong_param"]
        ]
    )
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_callable_invalid_combined_lockout_param(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )


class ClientCacheKeyTestCase(AxesTestCase):
    def test_get_cache_keys(self):
        """
        Test the cache key format.
        """

        cache_hash_digest = sha256(self.ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(request))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=self.ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))

    def test_get_cache_key_empty_ip_address(self):
        """
        Simulate an empty IP address in the request.
        """

        empty_ip_address = ""

        cache_hash_digest = sha256(empty_ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/",
            data={"username": self.username, "password": "test"},
            REMOTE_ADDR=empty_ip_address,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(request))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=empty_ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))

    def test_get_cache_key_credentials(self):
        """
        Test the cache key format.
        """

        ip_address = self.ip_address
        cache_hash_digest = sha256(ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        # Difference between the upper test: new call signature with credentials
        credentials = {"username": self.username}

        self.assertEqual([cache_hash_key], get_client_cache_keys(request, credentials))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )
        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))


class UsernameTestCase(AxesTestCase):
    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_default_get_client_username(self):
        expected = "test-username"

        request = HttpRequest()
        request.POST["username"] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    def test_default_get_client_username_drf(self):
        class DRFRequest:
            def __init__(self):
                self.data = {}
                self.POST = {}

        expected = "test-username"

        request = DRFRequest()
        request.data["username"] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_default_get_client_username_credentials(self):
        expected = "test-username"
        expected_in_credentials = "test-credentials-username"

        request = HttpRequest()
        request.POST["username"] = expected
        credentials = {"username": expected_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    def sample_customize_username(request, credentials):
        return "prefixed-" + request.POST.get("username")

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username)
    def test_custom_get_client_username_from_request(self):
        provided = "test-username"
        expected = "prefixed-" + provided
        provided_in_credentials = "test-credentials-username"

        request = HttpRequest()
        request.POST["username"] = provided
        credentials = {"username": provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected, actual)

    def sample_customize_username_credentials(request, credentials):
        return "prefixed-" + credentials.get("username")

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username_credentials)
    def test_custom_get_client_username_from_credentials(self):
        provided = "test-username"
        provided_in_credentials = "test-credentials-username"
        expected_in_credentials = "prefixed-" + provided_in_credentials

        request = HttpRequest()
        request.POST["username"] = provided
        credentials = {"username": provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    @override_settings(
        AXES_USERNAME_CALLABLE=lambda request, credentials: "example"
    )  # pragma: no cover
    def test_get_client_username(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), "example")

    @override_settings(AXES_USERNAME_CALLABLE=lambda request: None)  # pragma: no cover
    def test_get_client_username_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(
        AXES_USERNAME_CALLABLE=lambda request, credentials, extra: None
    )  # pragma: no cover
    def test_get_client_username_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE=True)
    def test_get_client_username_not_callable(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE="tests.test_helpers.get_username")
    def test_get_client_username_str(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), "username")


def get_username(request, credentials: dict) -> str:
    return "username"


def get_ip(request: HttpRequest) -> str:
    return "127.0.0.1"


class ClientIpAddressTestCase(AxesTestCase):
    @override_settings(AXES_CLIENT_IP_CALLABLE=get_ip)
    def test_get_client_ip_address(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(AXES_CLIENT_IP_CALLABLE="tests.test_helpers.get_ip")
    def test_get_client_ip_address_str(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(
        AXES_CLIENT_IP_CALLABLE=lambda request: "127.0.0.1"
    )  # pragma: no cover
    def test_get_client_ip_address_lambda(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(AXES_CLIENT_IP_CALLABLE=True)
    def test_get_client_ip_address_not_callable(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    @override_settings(AXES_CLIENT_IP_CALLABLE=lambda: None)  # pragma: no cover
    def test_get_client_ip_address_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    @override_settings(
        AXES_CLIENT_IP_CALLABLE=lambda request, extra: None
    )  # pragma: no cover
    def test_get_client_ip_address_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    def test_get_client_ip_address_with_ipware(self):
        request = HttpRequest()
        request.META["REMOTE_ADDR"] = "127.0.0.2"
        self.assertEqual(get_client_ip_address(request, use_ipware=True), "127.0.0.2")

    def test_get_client_ip_address_without_ipware(self):
        request = HttpRequest()
        request.META["REMOTE_ADDR"] = "127.0.0.3"
        self.assertEqual(get_client_ip_address(request, use_ipware=False), "127.0.0.3")


class IPWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = "POST"
        self.request.META["REMOTE_ADDR"] = "127.0.0.1"
        self.request.axes_ip_address = "127.0.0.1"

    @override_settings(AXES_IP_WHITELIST=None)
    def test_ip_in_whitelist_none(self):
        self.assertFalse(is_ip_address_in_whitelist("127.0.0.2"))

    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_ip_in_whitelist(self):
        self.assertTrue(is_ip_address_in_whitelist("127.0.0.1"))
        self.assertFalse(is_ip_address_in_whitelist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=None)
    def test_ip_in_blacklist_none(self):
        self.assertFalse(is_ip_address_in_blacklist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.1"])
    def test_ip_in_blacklist(self):
        self.assertTrue(is_ip_address_in_blacklist("127.0.0.1"))
        self.assertFalse(is_ip_address_in_blacklist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.1"])
    def test_is_client_ip_address_blacklisted_ip_in_blacklist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.2"])
    def test_is_is_client_ip_address_blacklisted_ip_not_in_blacklist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_blacklisted_ip_in_whitelist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.2"])
    def test_is_already_locked_ip_not_in_whitelist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_whitelisted_never_lockout(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_whitelisted_only_allow(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.2"])
    def test_is_client_ip_address_whitelisted_not(self):
        self.assertFalse(is_client_ip_address_whitelisted(self.request))


class MethodWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = "GET"

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_client_method_whitelisted(self):
        self.assertTrue(is_client_method_whitelisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_GET=False)
    def test_is_client_method_whitelisted_not(self):
        self.assertFalse(is_client_method_whitelisted(self.request))


class LockoutResponseTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()

    @override_settings(AXES_COOLOFF_TIME=42)
    def test_get_lockout_response_cool_off(self):
        get_lockout_response(request=self.request)

    @override_settings(AXES_LOCKOUT_TEMPLATE="example.html")
    @patch("axes.helpers.render")
    def test_get_lockout_response_lockout_template(self, render):
        self.assertFalse(render.called)
        get_lockout_response(request=self.request)
        self.assertTrue(render.called)

    @override_settings(AXES_LOCKOUT_URL="https://example.com")
    def test_get_lockout_response_lockout_url(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), HttpResponseRedirect)

    def test_get_lockout_response_lockout_json(self):
        self.request.META["HTTP_X_REQUESTED_WITH"] = "XMLHttpRequest"
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), JsonResponse)

    def test_get_lockout_response_lockout_response(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), HttpResponse)


def mock_get_cool_off_str(req):
    return timedelta(seconds=30)


class AxesCoolOffTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cool_off_none(self):
        self.assertIsNone(get_cool_off())

    @override_settings(AXES_COOLOFF_TIME=2)
    def test_get_cool_off_int(self):
        self.assertEqual(get_cool_off(), timedelta(hours=2))

    @override_settings(AXES_COOLOFF_TIME=2.0)
    def test_get_cool_off_float(self):
        self.assertEqual(get_cool_off(), timedelta(minutes=120))

    @override_settings(AXES_COOLOFF_TIME=0.25)
    def test_get_cool_off_float_lt_0(self):
        self.assertEqual(get_cool_off(), timedelta(minutes=15))

    @override_settings(AXES_COOLOFF_TIME=1.7)
    def test_get_cool_off_float_gt_0(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=6120))

    @override_settings(AXES_COOLOFF_TIME=lambda r: timedelta(seconds=30))
    def test_get_cool_off_callable(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))

    @override_settings(AXES_COOLOFF_TIME="tests.test_helpers.mock_get_cool_off_str")
    def test_get_cool_off_path(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))


def mock_is_whitelisted(request, credentials):
    return True


class AxesWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create(username="jane.doe")
        self.request = HttpRequest()
        self.credentials = dict()

    def test_is_whitelisted(self):
        self.assertFalse(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=mock_is_whitelisted)
    def test_is_whitelisted_override_callable(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE="tests.test_helpers.mock_is_whitelisted")
    def test_is_whitelisted_override_path(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=42)
    def test_is_whitelisted_override_invalid(self):
        with self.assertRaises(TypeError):
            is_user_attempt_whitelisted(self.request, self.credentials)


def mock_get_lockout_response(request, credentials):
    return HttpResponse(status=400)


def mock_get_lockout_response_with_original_response_param(
    request, response, credentials
):
    return HttpResponse(status=400)


class AxesLockoutTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.response = HttpResponse()
        self.credentials = dict()

    def test_get_lockout_response(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(429, response.status_code)

    @override_settings(AXES_HTTP_RESPONSE_CODE=403)
    def test_get_lockout_response_with_custom_http_response_code(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(403, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=mock_get_lockout_response)
    def test_get_lockout_response_override_callable(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="tests.test_helpers.mock_get_lockout_response"
    )
    def test_get_lockout_response_override_path(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE=mock_get_lockout_response_with_original_response_param
    )
    def test_get_lockout_response_override_callable_with_original_response_param(self):
        response = get_lockout_response(self.request, self.response, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="tests.test_helpers.mock_get_lockout_response_with_original_response_param"
    )
    def test_get_lockout_response_override_path_with_original_response_param(self):
        response = get_lockout_response(self.request, self.response, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=42)
    def test_get_lockout_response_override_invalid(self):
        with self.assertRaises(TypeError):
            get_lockout_response(self.request, self.credentials)


class AxesCleanseParamsTestCase(AxesTestCase):
    def setUp(self):
        self.parameters = {
            "username": "test_user",
            "password": "test_password",
            "other_sensitive_data": "sensitive",
        }

    @override_settings(AXES_SENSITIVE_PARAMETERS=[])
    def test_cleanse_parameters(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("sensitive", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=["other_sensitive_data"])
    def test_cleanse_parameters_override_sensitive(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("********************", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=["other_sensitive_data"])
    @override_settings(AXES_PASSWORD_FORM_FIELD="username")
    def test_cleanse_parameters_override_both(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("********************", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("********************", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=[])
    @override_settings(AXES_PASSWORD_FORM_FIELD=None)
    def test_cleanse_parameters_override_empty(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("sensitive", cleansed["other_sensitive_data"])
