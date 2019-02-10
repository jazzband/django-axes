from django.core.checks import run_checks, Error
from django.test import TestCase, override_settings

from axes.checks import Messages, Hints, Codes
from axes.conf import settings


class CacheCheckTestCase(TestCase):
    @override_settings(
        AXES_CACHE='nonexistent',
    )
    def test_cache_missing_produces_check_error(self):
        errors = run_checks()
        error = Error(
            msg=Messages.CACHE_MISSING,
            hint=Hints.CACHE_MISSING,
            obj=settings.CACHES,
            id=Codes.CACHE_MISSING,
        )

        self.assertIn(error, errors)

    @override_settings(
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
