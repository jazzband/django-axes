from django.core.checks import Tags, Warning, register  # pylint: disable=redefined-builtin

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
    BACKEND_INVALID = (
        "You do not have 'axes.backends.AxesBackend' in your settings.AUTHENTICATION_BACKENDS."
    )


class Hints:
    CACHE_INVALID = None
    MIDDLEWARE_INVALID = None
    BACKEND_INVALID = 'AxesModelBackend was renamed to AxesBackend in django-axes version 5.0.'


class Codes:
    CACHE_INVALID = 'axes.W001'
    MIDDLEWARE_INVALID = 'axes.W002'
    BACKEND_INVALID = 'axes.W003'


@register(Tags.security, Tags.caches, Tags.compatibility)
def axes_cache_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    axes_handler = getattr(settings, 'AXES_HANDLER', '')

    axes_cache_key = getattr(settings, 'AXES_CACHE', 'default')
    axes_cache_config = settings.CACHES.get(axes_cache_key, {})
    axes_cache_backend = axes_cache_config.get('BACKEND', '')

    axes_cache_backend_incompatible = [
        'django.core.cache.backends.dummy.DummyCache',
        'django.core.cache.backends.locmem.LocMemCache',
        'django.core.cache.backends.filebased.FileBasedCache',
    ]

    errors = []

    if axes_handler == 'axes.handlers.cache.AxesCacheHandler':
        if axes_cache_backend in axes_cache_backend_incompatible:
            errors.append(Warning(
                msg=Messages.CACHE_INVALID,
                hint=Hints.CACHE_INVALID,
                id=Codes.CACHE_INVALID,
            ))

    return errors


@register(Tags.security, Tags.compatibility)
def axes_middleware_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    if 'axes.middleware.AxesMiddleware' not in settings.MIDDLEWARE:
        errors.append(Warning(
            msg=Messages.MIDDLEWARE_INVALID,
            hint=Hints.MIDDLEWARE_INVALID,
            id=Codes.MIDDLEWARE_INVALID,
        ))

    return errors


@register(Tags.security, Tags.compatibility)
def axes_backend_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    if 'axes.backends.AxesBackend' not in settings.AUTHENTICATION_BACKENDS:
        errors.append(Warning(
            msg=Messages.BACKEND_INVALID,
            hint=Hints.BACKEND_INVALID,
            id=Codes.BACKEND_INVALID,
        ))

    return errors
