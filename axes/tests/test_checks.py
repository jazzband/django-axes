from django.core.checks import run_checks, Error
from django.test import override_settings

from axes.checks import Messages, Hints, Codes
from axes.conf import settings
from axes.tests.base import AxesTestCase


@override_settings(AXES_HANDLER='axes.handlers.cache.AxesCacheHandler')
class CacheCheckTestCase(AxesTestCase):
    @override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache'}})
    def test_cache_check(self):
        errors = run_checks()
        self.assertEqual([], errors)

    @override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
    def test_cache_check_errors(self):
        errors = run_checks()
        error = Error(
            msg=Messages.CACHE_INVALID,
            hint=Hints.CACHE_INVALID,
            obj=settings.CACHES,
            id=Codes.CACHE_INVALID,
        )

        self.assertEqual([error], errors)
