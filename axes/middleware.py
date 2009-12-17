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
