from django.core.checks import Error, Tags, register

from axes.conf import settings


class Messages:
    CACHE_MISSING = 'missing cache configuration for AXES_CACHE'
    CACHE_INVALID = 'invalid cache configuration for settings.AXES_CACHE'


class Hints:
    CACHE_MISSING = (
        'django-axes needs to have a cache configured with settings.AXES_CACHE'
    )
    CACHE_INVALID = (
        'django-axes does not work properly with LocMemCache as the cache backend'
        ' please add e.g. a DummyCache backend and configure it with settings.AXES_CACHE'
    )


class Codes:
    CACHE_MISSING = 'axes.E001'
    CACHE_INVALID = 'axes.E002'


@register(Tags.caches)
def axes_cache_backend_check(app_configs, **kwargs):  # pylint: disable=unused-argument
    errors = []

    axes_cache_key = getattr(settings, 'AXES_CACHE', 'default')
    axes_cache_config = settings.CACHES.get(axes_cache_key, {})
    axes_cache_backend = axes_cache_config.get('BACKEND', '')

    axes_cache_incompatible_backends = [
        'django.core.cache.backends.locmem.LocMemCache',
    ]

    if not axes_cache_config:
        errors.append(Error(
            msg=Messages.CACHE_MISSING,
            hint=Hints.CACHE_MISSING,
            obj=settings.CACHES,
            id=Codes.CACHE_MISSING,
        ))

    if axes_cache_backend in axes_cache_incompatible_backends:
        errors.append(Error(
            msg=Messages.CACHE_INVALID,
            hint=Hints.CACHE_INVALID,
            obj=settings.CACHES,
            id=Codes.CACHE_INVALID,
        ))

    return errors
