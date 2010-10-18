from django.contrib import admin
from django.contrib.auth import views as auth_views
from axes.decorators import watch_login

class FailedLoginMiddleware(object):

    def __init__(self, *args, **kwargs):
        super(FailedLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the admin login page
        admin.site.login = watch_login(admin.site.login)

        # and the regular auth login page
        auth_views.login = watch_login(auth_views.login)

class FailedAdminLoginMiddleware(object):
    def __init__(self, *args, **kwargs):
        super(FailedAdminLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the admin login page
        admin.site.login = watch_login(admin.site.login)

class FailedAuthLoginMiddleware(object):
    def __init__(self, *args, **kwargs):
        super(FailedAuthLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the admin login page
        auth_views.login = watch_login(auth_views.login)
