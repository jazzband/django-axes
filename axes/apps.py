from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from django.contrib.auth.views import LoginView
        from django.utils.decorators import method_decorator

        from axes import signals    # we must load signals
        from axes.decorators import axes_dispatch
        from axes.decorators import axes_form_invalid

        LoginView.dispatch = method_decorator(axes_dispatch)(LoginView.dispatch)
        LoginView.form_invalid = method_decorator(axes_form_invalid)(LoginView.form_invalid)
