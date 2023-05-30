from django.core.checks import (  # pylint: disable=redefined-builtin
    Tags,
    Warning,
    register,
)
from django.utils.module_loading import import_string

from axes.backends import AxesStandaloneBackend
from axes.conf import settings


class Messages:
    CACHE_INVALID = (
        "You are using the django-axes cache handler for login attempt tracking."
        " Your cache configuration is however invalid and will not work correctly with django-axes."
        " This can leave security holes in your login systems as attempts are not tracked correctly."
        " Reconfigure settings.AXES_CACHE and settings.CACHES per django-axes configuration documentation."
    )
    MIDDLEWARE_INVALID = (
        "You do not have 'axes.middleware.AxesMiddleware' in your settings.MIDDLEWARE."
    )
    BACKEND_INVALID = "You do not have 'axes.backends.AxesStandaloneBackend' or a subclass in your settings.AUTHENTICATION_BACKENDS."
    SETTING_DEPRECATED = "You have a deprecated setting {deprecated_setting} configured in your project settings"
    CALLABLE_INVALID = "{callable_setting} is not a valid callable."


class Hints:
    CACHE_INVALID = None
    MIDDLEWARE_INVALID = None
    BACKEND_INVALID = "AxesModelBackend was renamed to AxesStandaloneBackend in django-axes version 5.0."
    SETTING_DEPRECATED = None
    CALLABLE_INVALID = None


class Codes:
    CACHE_INVALID = "axes.W001"
    MIDDLEWARE_INVALID = "axes.W002"
    BACKEND_INVALID = "axes.W003"
    SETTING_DEPRECATED = "axes.W004"
    CALLABLE_INVALID = "axes.W005"


@register(Tags.security, Tags.caches, Tags.compatibility)
def axes_cache_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    axes_handler = getattr(settings, "AXES_HANDLER", "")

    axes_cache_key = getattr(settings, "AXES_CACHE", "default")
    axes_cache_config = settings.CACHES.get(axes_cache_key, {})
    axes_cache_backend = axes_cache_config.get("BACKEND", "")

    axes_cache_backend_incompatible = [
        "django.core.cache.backends.dummy.DummyCache",
        "django.core.cache.backends.locmem.LocMemCache",
        "django.core.cache.backends.filebased.FileBasedCache",
    ]

    warnings = []

    if axes_handler == "axes.handlers.cache.AxesCacheHandler":
        if axes_cache_backend in axes_cache_backend_incompatible:
            warnings.append(
                Warning(
                    msg=Messages.CACHE_INVALID,
                    hint=Hints.CACHE_INVALID,
                    id=Codes.CACHE_INVALID,
                )
            )

    return warnings


@register(Tags.security, Tags.compatibility)
def axes_middleware_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    warnings = []

    if "axes.middleware.AxesMiddleware" not in settings.MIDDLEWARE:
        warnings.append(
            Warning(
                msg=Messages.MIDDLEWARE_INVALID,
                hint=Hints.MIDDLEWARE_INVALID,
                id=Codes.MIDDLEWARE_INVALID,
            )
        )

    return warnings


@register(Tags.security, Tags.compatibility)
def axes_backend_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    warnings = []

    found = False
    for name in settings.AUTHENTICATION_BACKENDS:
        try:
            backend = import_string(name)
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError(
                "Can not find module path defined in settings.AUTHENTICATION_BACKENDS"
            ) from e
        except ImportError as e:
            raise ImportError(
                "Can not import backend class defined in settings.AUTHENTICATION_BACKENDS"
            ) from e

        if issubclass(backend, AxesStandaloneBackend):
            found = True
            break

    if not found:
        warnings.append(
            Warning(
                msg=Messages.BACKEND_INVALID,
                hint=Hints.BACKEND_INVALID,
                id=Codes.BACKEND_INVALID,
            )
        )

    return warnings


@register(Tags.compatibility)
def axes_deprecation_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    warnings = []

    deprecated_settings = [
        "AXES_DISABLE_SUCCESS_ACCESS_LOG",
        "AXES_LOGGER",
        # AXES_PROXY_ and AXES_META_ parameters were updated to more explicit
        # AXES_IPWARE_PROXY_ and AXES_IPWARE_META_ prefixes in version 6.x
        "AXES_PROXY_ORDER",
        "AXES_PROXY_COUNT",
        "AXES_PROXY_TRUSTED_IPS",
        "AXES_META_PRECEDENCE_ORDER",
        # AXES_ONLY_USER_FAILURES, AXES_USE_USER_AGENT and
        # AXES_LOCK_OUT parameters were replaced with AXES_LOCKOUT_PARAMETERS
        # in version 6.x
        "AXES_ONLY_USER_FAILURES",
        "AXES_LOCK_OUT_BY_USER_OR_IP",
        "AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP",
        "AXES_USE_USER_AGENT",
    ]

    for deprecated_setting in deprecated_settings:
        try:
            getattr(settings, deprecated_setting)
            warnings.append(
                Warning(
                    msg=Messages.SETTING_DEPRECATED.format(
                        deprecated_setting=deprecated_setting
                    ),
                    hint=None,
                    id=Codes.SETTING_DEPRECATED,
                )
            )
        except AttributeError:
            pass

    return warnings


@register
def axes_conf_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    warnings = []

    callable_settings = [
        "AXES_CLIENT_IP_CALLABLE",
        "AXES_CLIENT_STR_CALLABLE",
        "AXES_LOCKOUT_CALLABLE",
        "AXES_USERNAME_CALLABLE",
        "AXES_WHITELIST_CALLABLE",
        "AXES_COOLOFF_TIME",
        "AXES_LOCKOUT_PARAMETERS",
    ]

    for callable_setting in callable_settings:
        value = getattr(settings, callable_setting)
        if not is_valid_callable(value):
            warnings.append(
                Warning(
                    msg=Messages.CALLABLE_INVALID.format(
                        callable_setting=callable_setting
                    ),
                    hint=Hints.CALLABLE_INVALID,
                    id=Codes.CALLABLE_INVALID,
                )
            )

    return warnings


def is_valid_callable(value) -> bool:
    if value is None:
        return True

    if callable(value):
        return True

    if isinstance(value, str):
        try:
            import_string(value)
        except ImportError:
            return False

    return True
