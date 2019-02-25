.. _migration:

Migration
=========

This page contains migration instructions between different Axes
versions so that users might more confidently upgrade their installations.

Migrating from Axes version 4 to 5
----------------------------------

Axes version 5 has a few differences compared to Axes 4.

You might need to search your own codebase and check if you need to change
API endpoints or names for compatibility reasons.

- Login and logout view monkey-patching was removed.
  Login monitoring is now implemented with signal handlers
  and locking users out is implemented with a combination
  of a custom authentication backend, middleware, and signals.
- ``axes.utils.reset`` was moved to ``axes.attempts.reset``.
- ``AxesModelBackend`` was renamed to ``AxesBackend``
  for better naming and preventing the risk of users accidentally
  upgrading without noticing that the APIs have changed.
- ``axes.backends.AxesModelBackend.RequestParameterRequired``
  exception was renamed and retyped from ``Exception`` to ``ValueError``.
  Exception was moved to ``axes.exception.AxesBackendRequestParameterRequired``.
- ``AxesBackend`` now raises a
  ``axes.exceptions.AxesBackendPermissionDenied``
  exception when user is locked out, which triggers signal handler
  to run on failed logins, checking user lockout statuses.
- Axes lockout signal handler now raises exception
  ``axes.exceptions.AxesSignalPermissionDenied`` on lockouts.
- ``AxesMiddleware`` was added to process lockout events.
  The middleware handles the ``axes.exception.AxesSignalPermissionDenied``
  exception and converts it to a lockout response.
- ``AXES_USERNAME_CALLABLE`` is now always called with two arguments,
  ``request`` and ``credentials`` instead of just ``request``.
