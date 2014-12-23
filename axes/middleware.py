from django.conf import settings
from django.contrib.auth import views as auth_views

from axes.decorators import watch_login


class FailedLoginMiddleware(object):
    def __init__(self, *args, **kwargs):
        super(FailedLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the auth login
        auth_views.login = watch_login(auth_views.login)


class ViewDecoratorMiddleware(object):
    """
    When the django_axes middleware is installed, by default it watches the
    django.auth.views.login.

    This middleware allows adding protection to other views without the need
    to change any urls or dectorate them manually.

    Add this middleware to your MIDDLEWARE settings after
    `axes.middleware.FailedLoginMiddleware` and before the django
    flatpages middleware.
    """
    watched_logins = getattr(
        settings, 'AXES_PROTECTED_LOGINS', (
            '/accounts/login/',
        )
    )

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path in self.watched_logins:
            return watch_login(view_func)(request, *view_args, **view_kwargs)

        return None
