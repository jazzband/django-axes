from __future__ import unicode_literals

from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        from axes.conf import settings as axes_settings
        if (axes_settings.AXES_FAILURE_LIMIT is not None and
                axes_settings.AXES_FAILURE_LIMIT_MAX_BY_USER is not None and
                axes_settings.AXES_FAILURE_LIMIT >=
                axes_settings.AXES_FAILURE_LIMIT_MAX_BY_USER):
            raise ImproperlyConfigured(
                'If both set, AXES_FAILURE_LIMIT must be less'
                ' than AXES_FAILURE_LIMIT_MAX_BY_USER'
            )

        if settings.CACHES[getattr(settings, 'AXES_CACHE', 'default')]['BACKEND'] == \
                'django.core.cache.backends.locmem.LocMemCache':
            raise ImproperlyConfigured(
                'django-axes does not work properly with LocMemCache as the default cache backend'
                ' please add e.g. a DummyCache backend for axes and configure it with AXES_CACHE'
            )

        from django.contrib.auth.views import LoginView
        from django.utils.decorators import method_decorator

        from axes import signals  # pylint: disable=unused-import,unused-variable

        from axes.decorators import axes_dispatch
        from axes.decorators import axes_form_invalid

        LoginView.dispatch = method_decorator(axes_dispatch)(LoginView.dispatch)
        LoginView.form_invalid = method_decorator(axes_form_invalid)(LoginView.form_invalid)
