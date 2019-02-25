from django.core.checks import Error, Tags, register

from axes.conf import settings


class Messages:
    CACHE_INVALID = 'invalid cache configuration for settings.AXES_CACHE'


class Hints:
    CACHE_INVALID = (
        'django-axes does not work properly with LocMemCache as the cache backend'
        ' please add e.g. a DummyCache backend and configure it with settings.AXES_CACHE'
    )


class Codes:
    CACHE_INVALID = 'axeslE001'


@register(Tags.caches)
def axes_cache_backend_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    axes_cache_key = getattr(settings, 'AXES_CACHE', 'default')
    axes_cache_config = settings.CACHES.get(axes_cache_key, {})
    axes_cache_backend = axes_cache_config.get('BACKEND', '')

    axes_cache_incompatible_backends = [
        'django.core.cache.backends.locmem.LocMemCache',
    ]

    axes_handler = getattr(settings, 'AXES_HANDLER', '')

    if axes_handler == 'axes.handlers.cache.AxesCacheHandler':
        if axes_cache_backend in axes_cache_incompatible_backends:
            errors.append(Error(
                msg=Messages.CACHE_INVALID,
                hint=Hints.CACHE_INVALID,
                obj=settings.CACHES,
                id=Codes.CACHE_INVALID,
            ))

    return errors
