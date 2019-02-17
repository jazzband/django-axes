from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest, JsonResponse, HttpResponseRedirect, HttpResponse
from django.test import TestCase, override_settings

from axes import get_version
from axes.utils import (
    get_cool_off_iso8601,
    get_client_str,
    get_client_username,
    get_lockout_response,
    is_client_ip_address_blacklisted,
    is_ip_address_in_blacklist,
    is_ip_address_in_whitelist,
    get_cache_timeout,
    is_client_username_whitelisted,
    is_client_ip_address_whitelisted)


def get_username(request: HttpRequest, credentials: dict) -> str:
    return 'username'


def get_expected_client_str(*args, **kwargs):
    client_str_template = '{{username: "{0}", ip_address: "{1}", user_agent: "{2}", path_info: "{3}"}}'
    return client_str_template.format(*args, **kwargs)


class VersionTestCase(TestCase):
    @patch('axes.__version__', 'test')
    def test_get_version(self):
        self.assertEqual(get_version(), 'test')


class CacheTestCase(TestCase):
    @override_settings(AXES_COOLOFF_TIME=3)  # hours
    def test_get_cache_timeout(self):
        timeout_seconds = float(60 * 60 * 3)
        self.assertEqual(get_cache_timeout(), timeout_seconds)


class UserTestCase(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create(username='jane.doe')
        self.request = HttpRequest()

    def test_is_client_username_whitelisted(self):
        with patch.object(self.user_model, 'nolockout', True, create=True):
            self.assertTrue(is_client_username_whitelisted(
                self.request,
                {self.user_model.USERNAME_FIELD: self.user.username},
            ))

    def test_is_client_username_whitelisted_not(self):
        self.assertFalse(is_client_username_whitelisted(
            self.request,
            {self.user_model.USERNAME_FIELD: self.user.username},
        ))

    def test_is_client_username_whitelisted_does_not_exist(self):
        self.assertFalse(is_client_username_whitelisted(
            self.request,
            {self.user_model.USERNAME_FIELD: 'not.' + self.user.username},
        ))


class TimestampTestCase(TestCase):
    def test_iso8601(self):
        """
        Test get_cool_off_iso8601 correctly translates datetime.timdelta to ISO 8601 formatted duration.
        """

        expected = {
            timedelta(days=1, hours=25, minutes=42, seconds=8):
                'P2DT1H42M8S',
            timedelta(days=7, seconds=342):
                'P7DT5M42S',
            timedelta(days=0, hours=2, minutes=42):
                'PT2H42M',
            timedelta(hours=20, seconds=42):
                'PT20H42S',
            timedelta(seconds=300):
                'PT5M',
            timedelta(seconds=9005):
                'PT2H30M5S',
            timedelta(minutes=9005):
                'P6DT6H5M',
            timedelta(days=15):
                'P15D'
        }

        for delta, iso_duration in expected.items():
            with self.subTest(iso_duration):
                self.assertEqual(get_cool_off_iso8601(delta), iso_duration)


class ClientStringTestCase(TestCase):
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = get_expected_client_str(username, ip_address, user_agent, path_info)
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details_tuple(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = ('admin', 'login')

        expected = get_expected_client_str(username, ip_address, user_agent, path_info[0])
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = get_expected_client_str(username, ip_address, user_agent, path_info)
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{username: "test@example.com", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = get_expected_client_str(username, ip_address, user_agent, path_info)
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{username: "test@example.com", ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = get_expected_client_str(username, ip_address, user_agent, path_info)
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip_address = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{ip_address: "127.0.0.1", user_agent: "Googlebot/2.1 (+http://www.googlebot.com/bot.html)", path_info: "/admin/"}'
        actual = get_client_str(username, ip_address, user_agent, path_info)

        self.assertEqual(expected, actual)


class UsernameTestCase(TestCase):
    @override_settings(AXES_USERNAME_FORM_FIELD='username')
    def test_default_get_client_username(self):
        expected = 'test-username'

        request = HttpRequest()
        request.POST['username'] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USERNAME_FORM_FIELD='username')
    def test_default_get_client_username_credentials(self):
        expected = 'test-username'
        expected_in_credentials = 'test-credentials-username'

        request = HttpRequest()
        request.POST['username'] = expected
        credentials = {
            'username': expected_in_credentials
        }

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    def sample_customize_username(request, credentials):
        return 'prefixed-' + request.POST.get('username')

    @override_settings(AXES_USERNAME_FORM_FIELD='username')
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username)
    def test_custom_get_client_username_from_request(self):
        provided = 'test-username'
        expected = 'prefixed-' + provided
        provided_in_credentials = 'test-credentials-username'
        expected_in_credentials = 'prefixed-' + provided_in_credentials

        request = HttpRequest()
        request.POST['username'] = provided
        credentials = {'username': provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected, actual)

    def sample_customize_username_credentials(request, credentials):
        return 'prefixed-' + credentials.get('username')

    @override_settings(AXES_USERNAME_FORM_FIELD='username')
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username_credentials)
    def test_custom_get_client_username_from_credentials(self):
        provided = 'test-username'
        expected = 'prefixed-' + provided
        provided_in_credentials = 'test-credentials-username'
        expected_in_credentials = 'prefixed-' + provided_in_credentials

        request = HttpRequest()
        request.POST['username'] = provided
        credentials = {'username': provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    @override_settings(AXES_USERNAME_CALLABLE=lambda request, credentials: 'example')  # pragma: no cover
    def test_get_client_username(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), 'example')

    @override_settings(AXES_USERNAME_CALLABLE=lambda request: None)  # pragma: no cover
    def test_get_client_username_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE=lambda request, credentials, extra: None)  # pragma: no cover
    def test_get_client_username_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE=True)
    def test_get_client_username_not_callable(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE='axes.tests.test_utils.get_username')
    def test_get_client_username_str(self):
        self.assertEqual(
            get_client_username(HttpRequest(), {}),
            'username',
        )


class WhitelistTestCase(TestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = 'POST'
        self.request.META['REMOTE_ADDR'] = '127.0.0.1'

    @override_settings(AXES_IP_WHITELIST=None)
    def test_ip_in_whitelist_none(self):
        self.assertFalse(is_ip_address_in_whitelist('127.0.0.2'))

    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_ip_in_whitelist(self):
        self.assertTrue(is_ip_address_in_whitelist('127.0.0.1'))
        self.assertFalse(is_ip_address_in_whitelist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=None)
    def test_ip_in_blacklist_none(self):
        self.assertFalse(is_ip_address_in_blacklist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.1'])
    def test_ip_in_blacklist(self):
        self.assertTrue(is_ip_address_in_blacklist('127.0.0.1'))
        self.assertFalse(is_ip_address_in_blacklist('127.0.0.2'))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.1'])
    def test_is_client_ip_address_blacklisted_ip_in_blacklist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_IP_BLACKLIST=['127.0.0.2'])
    def test_is_is_client_ip_address_blacklisted_ip_not_in_blacklist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_is_client_ip_address_blacklisted_ip_in_whitelist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.2'])
    def test_is_already_locked_ip_not_in_whitelist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_is_client_ip_address_whitelisted_never_lockout(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.1'])
    def test_is_client_ip_address_whitelisted_only_allow(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=['127.0.0.2'])
    def test_is_client_ip_address_whitelisted_not(self):
        self.assertFalse(is_client_ip_address_whitelisted(self.request))


class LockoutResponseTestCase(TestCase):
    def setUp(self):
        self.request = HttpRequest()

    @override_settings(AXES_COOLOFF_TIME=42)
    def test_get_lockout_response_cool_off(self):
        get_lockout_response(request=self.request)

    @override_settings(AXES_LOCKOUT_TEMPLATE='example.html')
    @patch('axes.utils.render')
    def test_get_lockout_response_lockout_template(self, render):
        self.assertFalse(render.called)
        get_lockout_response(request=self.request)
        self.assertTrue(render.called)

    @override_settings(AXES_LOCKOUT_URL='https://example.com')
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
