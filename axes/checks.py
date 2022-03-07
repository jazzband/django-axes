from django.core.checks import (  # pylint: disable=redefined-builtin
    Tags,
    Warning,
    register,
)
from django.utils.module_loading import import_string

from axes.backends import AxesBackend
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
    BACKEND_INVALID = "You do not have 'axes.backends.AxesBackend' or a subclass in your settings.AUTHENTICATION_BACKENDS."
    SETTING_DEPRECATED = "You have a deprecated setting {deprecated_setting} configured in your project settings"


class Hints:
    CACHE_INVALID = None
    MIDDLEWARE_INVALID = None
    BACKEND_INVALID = (
        "AxesModelBackend was renamed to AxesBackend in django-axes version 5.0."
    )
    SETTING_DEPRECATED = None


class Codes:
    CACHE_INVALID = "axes.W001"
    MIDDLEWARE_INVALID = "axes.W002"
    BACKEND_INVALID = "axes.W003"
    SETTING_DEPRECATED = "axes.W004"


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

        if issubclass(backend, AxesBackend):
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
