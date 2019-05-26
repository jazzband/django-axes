.. _architecture:

Architecture
============

Axes is based on the existing Django authentication backend
architecture and framework for recognizing users and aims to be
compatible with the stock design and implementation of Django
while offering extensibility and configurability for using the
Axes authentication monitoring and logging for users of the package
as well as 3rd party package vendors such as Django REST Framework,
Django Allauth, Python Social Auth and so forth.

The development of custom 3rd party package support are active goals,
but you should check the up-to-date documentation and implementation
of Axes for current compatibility before using Axes with custom solutions
and make sure that authentication monitoring is working correctly.

This document describes the Django authentication flow
and how Axes augments it to achieve authentication and login
monitoring and lock users out on too many access attempts.


Django authentication flow
--------------------------

When a user tries to log in in Django, the login is usually performed
by running a number of authentication backends that check user login
information by calling the ``django.contrib.auth.authenticate`` function.

If an authentication backend does not approve of a user login,
it can raise a ``django.core.exceptions.PermissionDenied`` exception.

If a login fails, Django then fires a
``from django.contrib.auth.signals.user_login_failed`` signal.

A normal login flow for Django runs as follows:

.. code-block:: text

    -  Login view is called by, for example,
       a user sending form data with browser.

    -  django.contrib.auth.authenticate is called by
       the view code to check the authentication request
       for credentials and return a user object matching them.

    -  AUTHENTICATION_BACKENDS are iterated over
       and their authenticate methods called one-by-one.

    -  An authentication backend either returns
       a user object which results in that user
       being logged in or returns None.
       If a PermissionDenied error is raised
       by any of the authentication backends
       the whole request authentication flow
       is aborted and signal handlers triggered.


Django Axes authentication flow
-------------------------------

Axes monitors logins with the ``user_login_failed`` signal handler
and after login attempts exceed the given maximum, starts blocking them.

Django emits the ``user_login_failed`` signal when an authentication backend
either raises the PermissionDenied signal or alternatively no authentication backend
manages to recognize a given authentication request and return a user for it.

The blocking is done by ``AxesBackend`` which checks every request
coming through the Django authentication flow and verifies they
are not blocked, and allows the requests to go through if the check passes.

If any of the checks fails, an exception is raised which interrupts
the login process and triggers the Django login failed signal handlers.

Axes implements the lockout flow as follows:

.. code-block:: text

    -  Login view is called.

    -  django.contrib.auth.authenticate is called.

    -  AUTHENTICATION_BACKENDS are iterated over
       where axes.backends.AxesBackend is the first.

    -  AxesBackend checks authentication request
       for lockout rules and either aborts the
       authentication flow or lets the authentication
       process proceed to the next configured
       authentication backend in the list.

    [Axes handler runs at this this stage if appropriate]

    -  If the user authentication request fails due to
       any reason, e.g. a lockout or wrong credentials,
       Axes receives authentication failure information
       via the axes.signals.handle_user_login_failed signal.

    -  The selected Axes handler is run to check
       the user login failure statistics and rules.

    [Axes default handler implements these steps]

    -  Axes logs the failure and increments the failure
       counters which keep track of failure statistics.
       Axes then updates the request object with a logout
       status flag that can be processed by
       view or middleware code as needed.

    -  AxesMiddleware processes the lockout request and response
       and returns a readable lockout message to the user.

This plugin assumes that the login views either call
the ``django.contrib.auth.authenticate`` method to log in users
or otherwise take care of notifying Axes of authentication
attempts or login failures the same way Django does.

The login flows can be customized and the Axes
authentication backend or middleware can be easily swapped.

.. image:: images/flow.png
   :alt: Django Axes augmented authentication flow
         with custom authentication backend,
         signal handlers, and middleware
