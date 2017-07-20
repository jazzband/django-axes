from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from django.contrib.auth.views import LoginView
        from django.utils.decorators import method_decorator

        from axes.decorators import watch_login

        LoginView.dispatch = method_decorator(watch_login)(LoginView.dispatch)
