from django.core.checks import run_checks, Error
from django.test import override_settings

from axes.checks import Messages, Hints, Codes
from axes.conf import settings
from axes.tests.base import AxesTestCase


class CacheCheckTestCase(AxesTestCase):
    @override_settings(
        AXES_HANDLER='axes.handlers.cache.AxesCacheHandler',
        AXES_CACHE='axes',
        CACHES={
            'axes': {
                'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            },
        },
    )
    def test_cache_misconfiguration_produces_check_error(self):
        errors = run_checks()
        error = Error(
            msg=Messages.CACHE_INVALID,
            hint=Hints.CACHE_INVALID,
            obj=settings.CACHES,
            id=Codes.CACHE_INVALID,
        )

        self.assertIn(error, errors)
