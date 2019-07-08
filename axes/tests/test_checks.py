from django.core.checks import run_checks, Warning  # pylint: disable=redefined-builtin
from django.test import override_settings, modify_settings

from axes.backends import AxesBackend
from axes.checks import Messages, Hints, Codes
from axes.tests.base import AxesTestCase


class CacheCheckTestCase(AxesTestCase):
    @override_settings(
        AXES_HANDLER='axes.handlers.cache.AxesCacheHandler',
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.db.DatabaseCache', 'LOCATION': 'axes_cache'}},
    )
    def test_cache_check(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(
        AXES_HANDLER='axes.handlers.cache.AxesCacheHandler',
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    )
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.CACHE_INVALID,
            hint=Hints.CACHE_INVALID,
            id=Codes.CACHE_INVALID,
        )

        self.assertEqual(warnings, [
            warning,
        ])

    @override_settings(
        AXES_HANDLER='axes.handlers.database.AxesDatabaseHandler',
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    )
    def test_cache_check_does_not_produce_check_warnings_with_database_handler(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])


class MiddlewareCheckTestCase(AxesTestCase):
    @modify_settings(
        MIDDLEWARE={
            'remove': ['axes.middleware.AxesMiddleware']
        },
    )
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.MIDDLEWARE_INVALID,
            hint=Hints.MIDDLEWARE_INVALID,
            id=Codes.MIDDLEWARE_INVALID,
        )

        self.assertEqual(warnings, [
            warning,
        ])


class MyBackend(AxesBackend):
    pass


class BackendCheckTestCase(AxesTestCase):
    @modify_settings(
        AUTHENTICATION_BACKENDS={
            'remove': ['axes.backends.AxesBackend']
        },
    )
    def test_backend_missing(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.BACKEND_INVALID,
            hint=Hints.BACKEND_INVALID,
            id=Codes.BACKEND_INVALID,
        )

        self.assertEqual(warnings, [
            warning,
        ])

    @override_settings(
        AUTHENTICATION_BACKENDS=[__name__ + "." + MyBackend.__name__]
    )
    def test_custom_backend(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])


class DeprecatedSettingsTestCase(AxesTestCase):
    def setUp(self):
        self.disable_success_access_log_warning = Warning(
            msg=Messages.SETTING_DEPRECATED.format(deprecated_setting='AXES_DISABLE_SUCCESS_ACCESS_LOG'),
            hint=Hints.SETTING_DEPRECATED,
            id=Codes.SETTING_DEPRECATED,
        )

    @override_settings(
        AXES_DISABLE_SUCCESS_ACCESS_LOG=True,
    )
    def test_deprecated_success_access_log_flag(self):
        warnings = run_checks()
        self.assertEqual(warnings, [
            self.disable_success_access_log_warning,
        ])
