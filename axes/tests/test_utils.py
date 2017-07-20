import datetime

from django.test import TestCase, override_settings
from django.utils import six

from axes.utils import iso8601, is_ipv6, get_client_str


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
        self.assertTrue(is_ipv6('ff80::220:16ff:fec9:1'))
        self.assertFalse(is_ipv6('67.255.125.204'))
        self.assertFalse(is_ipv6('foo'))

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_ip_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = ip
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_ONLY_USER_FAILURES=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_only_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = username
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = '{0} from {1}'.format(username, ip)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        expected = details.format(username, ip, user_agent, path_info)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USE_USER_AGENT=True)
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_agent_client_details(self):
        username = 'test@example.com'
        ip = '127.0.0.1'
        user_agent = 'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
        path_info = '/admin/'

        expected = ip + '(user-agent={0})'.format(user_agent)
        actual = get_client_str(username, ip, user_agent, path_info)

        self.assertEqual(expected, actual)
