from django.test import TestCase, override_settings

from axes.conf import settings
from axes.utils import get_ip


class MockRequest:
    def __init__(self):
        self.META = dict()


@override_settings(AXES_BEHIND_REVERSE_PROXY=True)
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


@override_settings(AXES_BEHIND_REVERSE_PROXY=True)
@override_settings(AXES_REVERSE_PROXY_HEADER='HTTP_X_FORWARDED_FOR')
@override_settings(AXES_NUM_PROXIES=2)
class GetIPNumProxiesTest(TestCase):
    """Test that get_ip returns the correct last IP when NUM_PROXIES is configured
    """
    def setUp(self):
        self.request = MockRequest()

    def test_header_ordering(self):
        self.ip = '2.2.2.2'

        valid_headers = [
            '4.4.4.4, 3.3.3.3, 2.2.2.2, 1.1.1.1',
            '         3.3.3.3, 2.2.2.2, 1.1.1.1',
            '                  2.2.2.2, 1.1.1.1',
        ]

        for header in valid_headers:
            self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = header
            self.assertEqual(self.ip, get_ip(self.request))

    def test_invalid_headers_too_few(self):
        self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = '1.1.1.1'
        with self.assertRaises(Warning):
            get_ip(self.request)

    def test_invalid_headers_no_ip(self):
        self.request.META[settings.AXES_REVERSE_PROXY_HEADER] = ''
        with self.assertRaises(Warning):
            get_ip(self.request)


@override_settings(AXES_BEHIND_REVERSE_PROXY=True)
@override_settings(AXES_REVERSE_PROXY_HEADER='HTTP_X_AXES_CUSTOM_HEADER')
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
