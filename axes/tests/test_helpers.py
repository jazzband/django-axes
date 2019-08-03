from datetime import timedelta
from unittest.mock import patch

from django.test import override_settings

from axes.helpers import get_cool_off
from axes.tests.base import AxesTestCase


def get_cool_off_str():
    return timedelta(seconds=30)


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

    @override_settings(AXES_COOLOFF_TIME='axes.tests.test_helpers.get_cool_off_str')
    def test_get_cool_off_str(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))
