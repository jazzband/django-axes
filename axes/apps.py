from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from django.contrib.auth.views import LoginView
        from axes.decorators import watch_login

        LoginView.dispatch = watch_login(LoginView.dispatch)
