from django.core.checks import Error, Tags, register

from axes.conf import settings


class Messages:
    CACHE_INVALID = 'invalid cache configuration for settings.AXES_CACHE'
    MIDDLEWARE_INVALID = 'axes.middleware.AxesMiddleware not in settings.MIDDLEWARE'
    BACKEND_INVALID = 'axes.backends.AxesBackend not in settings.AUTHENTICATION_BACKENDS'


class Hints:
    CACHE_INVALID = (
        'django-axes does not work properly with LocMemCache as the cache backend.'
        ' Please check the django-axes documentation and reconfigure settings.AXES_CACHE.'
    )
    MIDDLEWARE_INVALID = (
        'django-axes does not work properly without axes.middleware.AxesMiddleware in settings.MIDDLEWARE.'
        ' Please check the django-axes documentation and reconfigure settings.MIDDLEWARE.'
    )
    BACKEND_INVALID = (
        'django-axes does not work properly without axes.backends.AxesBackend in settings.AUTHENTICATION_BACKENDS.'
        ' Please check the django-axes documentation and reconfigure settings.AUTHENTICATION_BACKENDS.'
        ' Please note that the backend name was changed from AxesModelBackend to AxesBackend in django-axes version 5.'
    )


class Codes:
    CACHE_INVALID = 'axes.E001'
    MIDDLEWARE_INVALID = 'axes.E002'
    BACKEND_INVALID = 'axes.E003'


@register(Tags.compatibility, Tags.caches)
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
            errors.append(Error(
                msg=Messages.CACHE_INVALID,
                hint=Hints.CACHE_INVALID,
                obj=settings.CACHES,
                id=Codes.CACHE_INVALID,
            ))

    return errors


@register(Tags.compatibility)
def axes_middleware_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    if 'axes.middleware.AxesMiddleware' not in settings.MIDDLEWARE:
        errors.append(Error(
            msg=Messages.MIDDLEWARE_INVALID,
            hint=Hints.MIDDLEWARE_INVALID,
            obj=settings.MIDDLEWARE,
            id=Codes.MIDDLEWARE_INVALID,
        ))

    return errors


@register(Tags.compatibility)
def axes_backend_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    if 'axes.backends.AxesBackend' not in settings.AUTHENTICATION_BACKENDS:
        errors.append(Error(
            msg=Messages.BACKEND_INVALID,
            hint=Hints.BACKEND_INVALID,
            obj=settings.AUTHENTICATION_BACKENDS,
            id=Codes.BACKEND_INVALID,
        ))

    return errors
