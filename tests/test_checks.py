from django.core.checks import run_checks, Warning  # pylint: disable=redefined-builtin
from django.test import override_settings, modify_settings

from axes.backends import AxesStandaloneBackend
from axes.checks import Messages, Hints, Codes
from tests.base import AxesTestCase


class CacheCheckTestCase(AxesTestCase):
    @override_settings(
        AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.db.DatabaseCache",
                "LOCATION": "axes_cache",
            }
        },
    )
    def test_cache_check(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(
        AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.CACHE_INVALID, hint=Hints.CACHE_INVALID, id=Codes.CACHE_INVALID
        )

        self.assertEqual(warnings, [warning])

    @override_settings(
        AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_cache_check_does_not_produce_check_warnings_with_database_handler(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])


class MiddlewareCheckTestCase(AxesTestCase):
    @modify_settings(MIDDLEWARE={"remove": ["axes.middleware.AxesMiddleware"]})
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.MIDDLEWARE_INVALID,
            hint=Hints.MIDDLEWARE_INVALID,
            id=Codes.MIDDLEWARE_INVALID,
        )

        self.assertEqual(warnings, [warning])


class AxesSpecializedBackend(AxesStandaloneBackend):
    pass


class BackendCheckTestCase(AxesTestCase):
    @modify_settings(
        AUTHENTICATION_BACKENDS={"remove": ["axes.backends.AxesStandaloneBackend"]}
    )
    def test_backend_missing(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.BACKEND_INVALID,
            hint=Hints.BACKEND_INVALID,
            id=Codes.BACKEND_INVALID,
        )

        self.assertEqual(warnings, [warning])

    @override_settings(
        AUTHENTICATION_BACKENDS=["tests.test_checks.AxesSpecializedBackend"]
    )
    def test_specialized_backend(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(
        AUTHENTICATION_BACKENDS=["tests.test_checks.AxesNotDefinedBackend"]
    )
    def test_import_error(self):
        with self.assertRaises(ImportError):
            run_checks()

    @override_settings(AUTHENTICATION_BACKENDS=["module.not_defined"])
    def test_module_not_found_error(self):
        with self.assertRaises(ModuleNotFoundError):
            run_checks()


class DeprecatedSettingsTestCase(AxesTestCase):
    def setUp(self):
        self.disable_success_access_log_warning = Warning(
            msg=Messages.SETTING_DEPRECATED.format(
                deprecated_setting="AXES_DISABLE_SUCCESS_ACCESS_LOG"
            ),
            hint=Hints.SETTING_DEPRECATED,
            id=Codes.SETTING_DEPRECATED,
        )

    @override_settings(AXES_DISABLE_SUCCESS_ACCESS_LOG=True)
    def test_deprecated_success_access_log_flag(self):
        warnings = run_checks()
        self.assertEqual(warnings, [self.disable_success_access_log_warning])


class ConfCheckTestCase(AxesTestCase):
    @override_settings(AXES_USERNAME_CALLABLE="module.not_defined")
    def test_invalid_import_path(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.CALLABLE_INVALID.format(
                callable_setting="AXES_USERNAME_CALLABLE"
            ),
            hint=Hints.CALLABLE_INVALID,
            id=Codes.CALLABLE_INVALID,
        )
        self.assertEqual(warnings, [warning])

    @override_settings(AXES_COOLOFF_TIME=lambda: 1)
    def test_valid_callable(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])
