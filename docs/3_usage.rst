.. _usage:

Usage
=====

Once Axes is is installed and configured, you can login and logout
of your application via the ``django.contrib.auth`` views.
The attempts will be logged and visible in the Access Attempts section in admin.

Axes monitors the views by using the Django login and logout signals and
locks out user attempts with a custom authentication backend that checks
if requests are allowed to authenticate per the configured rules.

By default, Axes will lock out repeated access attempts from the same IP address
by monitoring login failures and storing them into the default database.


Authenticating users
--------------------

Axes needs a ``request`` attribute to be supplied to the stock Django ``authenticate``
method in the ``django.contrib.auth`` module in order to function correctly.

If you wish to manually supply the argument to the calls to ``authenticate``,
you can use the following snippet in your custom login views, tests, or other code::


    def custom_login_view(request)
        username = ...
        password = ...

        user = authenticate(
            request=request,  # this is the important custom argument
            username=username,
            password=password,
        )

        if user is not None:
            login(request, user)


If your test setup has problems with the ``request`` argument, you can either
supply the argument manually with a blank `HttpRequest()`` object,
disable Axes in the test setup by excluding ``axes`` from ``INSTALLED_APPS``,
or leave out ``axes.backends.AxesBackend`` from your ``AUTHENTICATION_BACKENDS``.

If you are using a 3rd party library that does not supply the ``request`` attribute
when calling ``authenticate`` you can implement a customized backend that inherits
from ``axes.backends.AxesBackend`` or other backend and overrides the ``authenticate`` method.


Resetting attempts and lockouts
-------------------------------

When Axes locks an IP address, it is not allowed to login again.
You can allow IPs to attempt again by resetting (deleting)
the relevant AccessAttempt records in the admin UI, CLI, or your own code.

You can also configure automatic cool down periods, IP whitelists, and custom
code and handler functions for resetting attempts. Please check out the
configuration and customization documentation for further information.

.. note::
   Please note that the functionality describe here concerns the default
   database handler. If you have changed the default handler to another
   class such as the cache handler you have to implement custom reset commands.


Resetting attempts from the Django admin UI
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Records can be easily deleted by using the Django admin application.

Go to the admin UI and check the ``Access Attempt`` view.
Select the attempts you wish the allow again and simply remove them.
The blocked user will be allowed to log in again in accordance to the rules.


Resetting attempts from command line
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Axes offers a command line interface with
``axes_reset``, ``axes_reset_ip``, and ``axes_reset_username``
management commands with the Django ``manage.py`` or ``django-admin`` command helpers:

- ``python manage.py axes_reset``
  will reset all lockouts and access records.
- ``python manage.py axes_reset_ip [ip ...]``
  will clear lockouts and records for the given IP addresses.
- ``python manage.py axes_reset_username [username ...]``
  will clear lockouts and records for the given usernames.
- ``python manage.py axes_reset_logs (age)``
  will reset (i.e. delete) AccessLog records that are older
  than the given age where the default is 30 days.


Resetting attempts programmatically by APIs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In your code, you can use the ``axes.utils.reset`` function.

- ``reset()`` will reset all lockouts and access records.
- ``reset(ip=ip)`` will clear lockouts and records for the given IP address.
- ``reset(username=username)`` will clear lockouts and records for the given username.

.. note::
   Please note that if you give both ``username`` and ``ip`` arguments to ``reset``
   that attempts that have both the set IP and username are reset.
   The effective behaviour of ``reset`` is to ``and`` the terms instead of ``or`` ing them.
