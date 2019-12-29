from datetime import timedelta

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import override_settings

from axes.helpers import get_cool_off, is_user_attempt_whitelisted
from axes.tests.base import AxesTestCase


def get_cool_off_str():
    return timedelta(seconds=30)


def is_whitelisted(request, credentials):
    return True


class AxesHelpersTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cool_off_none(self):
        self.assertIsNone(get_cool_off())

    @override_settings(AXES_COOLOFF_TIME=2)
    def test_get_cool_off_int(self):
        self.assertEqual(get_cool_off(), timedelta(hours=2))

    @override_settings(AXES_COOLOFF_TIME=lambda: timedelta(seconds=30))
    def test_get_cool_off_callable(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))

    @override_settings(AXES_COOLOFF_TIME="axes.tests.test_helpers.get_cool_off_str")
    def test_get_cool_off_str(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))


class UserWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create(username="jane.doe")
        self.request = HttpRequest()
        self.credentials = dict()

    def test_is_whitelisted(self):
        self.assertFalse(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=is_whitelisted)
    def test_is_whitelisted_override(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE="axes.tests.test_helpers.is_whitelisted")
    def test_is_whitelisted_override_path(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=42)
    def test_is_whitelisted_override_invalid(self):
        with self.assertRaises(TypeError):
            is_user_attempt_whitelisted(self.request, self.credentials)
