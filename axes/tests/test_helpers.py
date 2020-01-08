from datetime import timedelta

from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse
from django.test import override_settings

from axes.helpers import get_cool_off, get_lockout_response, is_user_attempt_whitelisted
from axes.tests.base import AxesTestCase


def mock_get_cool_off_str():
    return timedelta(seconds=30)


class AxesCoolOffTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cool_off_none(self):
        self.assertIsNone(get_cool_off())

    @override_settings(AXES_COOLOFF_TIME=2)
    def test_get_cool_off_int(self):
        self.assertEqual(get_cool_off(), timedelta(hours=2))

    @override_settings(AXES_COOLOFF_TIME=lambda: timedelta(seconds=30))
    def test_get_cool_off_callable(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))

    @override_settings(
        AXES_COOLOFF_TIME="axes.tests.test_helpers.mock_get_cool_off_str"
    )
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

    @override_settings(
        AXES_WHITELIST_CALLABLE="axes.tests.test_helpers.mock_is_whitelisted"
    )
    def test_is_whitelisted_override_path(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=42)
    def test_is_whitelisted_override_invalid(self):
        with self.assertRaises(TypeError):
            is_user_attempt_whitelisted(self.request, self.credentials)


def mock_get_lockout_response(request, credentials):
    return HttpResponse(status=400)


class AxesLockoutTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.credentials = dict()

    def test_get_lockout_response(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(403, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=mock_get_lockout_response)
    def test_get_lockout_response_override_callable(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="axes.tests.test_helpers.mock_get_lockout_response"
    )
    def test_get_lockout_response_override_path(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=42)
    def test_get_lockout_response_override_invalid(self):
        with self.assertRaises(TypeError):
            get_lockout_response(self.request, self.credentials)
