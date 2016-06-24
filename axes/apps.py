from django import apps


class AppConfig(apps.AppConfig):
    name = 'axes'

    def ready(self):
        from django.contrib.auth import views as auth_views
        from axes.decorators import watch_login

        auth_views.login = watch_login(auth_views.login)
