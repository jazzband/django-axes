from __future__ import absolute_import

import logging

from django import apps

from .conf import settings


log = logging.getLogger(settings.AXES_LOGGER)


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from . import signals    # NOQA: Load the signals module to bind the receivers

        if settings.USE_LEGACY_LOGIN_VIEW_PATCH:
            log.warning('Automatic patching of LoginView using AXES_USE_LEGACY_LOGIN_VIEW_PATCH is deprecated. '
                        'use axes.views.AxesLoginView instead, or add axes.views.AxesLoginMixin to your custom login view.')
            from django.contrib.auth.views import LoginView
            from django.utils.decorators import method_decorator

            from .decorators import axes_dispatch, axes_form_invalid

            LoginView.dispatch = method_decorator(axes_dispatch)(LoginView.dispatch)
            LoginView.form_invalid = method_decorator(axes_form_invalid)(LoginView.form_invalid)
