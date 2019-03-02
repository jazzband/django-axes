.. _upgrading:

Upgrading
=========

This page contains upgrade instructions between different Axes
versions so that users might more confidently upgrade their installations.

Upgrading from Axes version 4 to 5
----------------------------------

Axes version 5 has a few differences compared to Axes 4.

- Login and logout view monkey-patching was removed.
  Login monitoring is now implemented with signal handlers
  and locking users out is implemented with a combination
  of a custom authentication backend, middleware, and signals.
  This does not change existing logic, but is good to know.
- The old decorators function as before and their behaviour is the same.
- ``AXES_USERNAME_CALLABLE`` is now always called with two arguments,
  (``request``, ``credentials``) instead of just ``request``.
  If you have implemented a custom callable, you need to add
  the second ``credentials`` argument to the function signature.
- ``AXES_USERNAME_CALLABLE`` now supports string paths in addition to callables.
- ``axes.backends.AxesModelBackend.RequestParameterRequired``
  exception was renamed and retyped from ``Exception`` to ``ValueError``.
  Exception was moved to ``axes.exception.AxesModelBackendRequestParameterRequired``.
- ``AxesModelBackend`` now raises a
  ``axes.exceptions.AxesModelBackendPermissionDenied``
  exception when user is locked out, which triggers signal handler
  to run on failed logins, checking user lockout statuses.
- Axes lockout signal handler now raises a
  ``axes.exceptions.AxesHandlerPermissionDenied`` exception on lockouts.
- ``AxesMiddleware`` was added to process lockout events.
  The middleware handles the ``axes.exception.AxesHandlerPermissionDenied``
  exception and converts it to a lockout response.
