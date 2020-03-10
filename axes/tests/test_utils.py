from datetime import timedelta
from hashlib import md5
from unittest.mock import patch

from django.http import JsonResponse, HttpResponseRedirect, HttpResponse, HttpRequest
from django.test import override_settings, RequestFactory

from axes.apps import AppConfig
from axes.models import AccessAttempt
from axes.tests.base import AxesTestCase
from axes.helpers import (
    get_cache_timeout,
    get_client_str,
    get_client_username,
    get_client_cache_key,
    get_client_parameters,
    get_cool_off_iso8601,
    get_lockout_response,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_ip_address_in_blacklist,
    is_ip_address_in_whitelist,
    is_client_method_whitelisted,
    toggleable,
)


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
            username, ip_address, user_agent, path_info
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_imbalanced_quotes(self):
        username = "butterfly.. },,,"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details_tuple(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = ("admin", "login")

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info[0]
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_ip_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info
        )
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", user_agent: "Googlebot/2.1 (+http://www.googlebot.com/bot.html)", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)


class ClientParametersTestCase(AxesTestCase):
    @override_settings(AXES_ONLY_USER_FAILURES=True)
    def test_get_filter_kwargs_user(self):
        self.assertEqual(
            dict(
                get_client_parameters(self.username, self.ip_address, self.user_agent)
            ),
            {"username": self.username},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=False,
        AXES_USE_USER_AGENT=False,
    )
    def test_get_filter_kwargs_ip(self):
        self.assertEqual(
            dict(
                get_client_parameters(self.username, self.ip_address, self.user_agent)
            ),
            {"ip_address": self.ip_address},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True,
        AXES_USE_USER_AGENT=False,
    )
    def test_get_filter_kwargs_user_and_ip(self):
        self.assertEqual(
            dict(
                get_client_parameters(self.username, self.ip_address, self.user_agent)
            ),
            {"username": self.username, "ip_address": self.ip_address},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=False,
        AXES_USE_USER_AGENT=True,
    )
    def test_get_filter_kwargs_ip_and_agent(self):
        self.assertEqual(
            dict(
                get_client_parameters(self.username, self.ip_address, self.user_agent)
            ),
            {"ip_address": self.ip_address, "user_agent": self.user_agent},
        )

    @override_settings(
        AXES_ONLY_USER_FAILURES=False,
        AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True,
        AXES_USE_USER_AGENT=True,
    )
    def test_get_filter_kwargs_user_ip_agent(self):
        self.assertEqual(
            dict(
                get_client_parameters(self.username, self.ip_address, self.user_agent)
            ),
            {
                "username": self.username,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
            },
        )


class ClientCacheKeyTestCase(AxesTestCase):
    def test_get_cache_key(self):
        """
        Test the cache key format.
        """

        cache_hash_digest = md5(self.ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        self.assertEqual(cache_hash_key, get_client_cache_key(request))

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

        self.assertEqual(cache_hash_key, get_client_cache_key(attempt))

    def test_get_cache_key_empty_ip_address(self):
        """
        Simulate an empty IP address in the request.
        """

        empty_ip_address = ""

        cache_hash_digest = md5(empty_ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/",
            data={"username": self.username, "password": "test"},
            REMOTE_ADDR=empty_ip_address,
        )

        self.assertEqual(cache_hash_key, get_client_cache_key(request))

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

        self.assertEqual(cache_hash_key, get_client_cache_key(attempt))

    def test_get_cache_key_credentials(self):
        """
        Test the cache key format.
        """

        ip_address = self.ip_address
        cache_hash_digest = md5(ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        # Difference between the upper test: new call signature with credentials
        credentials = {"username": self.username}

        self.assertEqual(cache_hash_key, get_client_cache_key(request, credentials))

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
        self.assertEqual(cache_hash_key, get_client_cache_key(attempt))


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

    @override_settings(AXES_USERNAME_CALLABLE="axes.tests.test_utils.get_username")
    def test_get_client_username_str(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), "username")


def get_username(request, credentials: dict) -> str:
    return "username"


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
        self.request.is_ajax = lambda: True
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), JsonResponse)

    def test_get_lockout_response_lockout_response(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), HttpResponse)
