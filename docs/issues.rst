.. _issues:

Issues
======

Not being locked out after failed attempts
------------------------------------------

You may find that Axes is not capturing your failed login attempts. It may
be that you need to manually add watch_login to your login url.

For example, in your urls.py::

    ...
    from my.custom.app import login
    from axes.decorators import watch_login
    ...
    urlpatterns = patterns('',
        (r'^login/$', watch_login(login)),
    ...


Locked out without reason
-------------------------

It may happen that you have suddenly become locked out without a single failed
attempt. One possible reason is that you are using some custom login form and the
username field is named something different than "username", e.g. "email". This
leads to all users attempts being lumped together. To fix this add the following
to your settings:

    AXES_USERNAME_FORM_FIELD = "email"

