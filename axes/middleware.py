from django.contrib.auth import views as auth_views

from axes.decorators import watch_login


class FailedLoginMiddleware(object):
    def __init__(self, *args, **kwargs):
        super(FailedLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the auth login
        auth_views.login = watch_login(auth_views.login)
