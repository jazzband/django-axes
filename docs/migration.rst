.. _migration:

Migration
=========

This page contains migration instructions between different django-axes
versions so that users might more confidently upgrade their installations.

From django-axes version 4 to version 5
---------------------------------------

Application version 5 has a few differences compared to django-axes 4.

You might need to search your own codebase and check if you need to change
API endpoints or names for compatibility reasons.

- Login and logout view monkey-patching was removed.
  Login monitoring is now implemented with signals
  and locking users out is implemented with a combination
  of a custom authentication backend, middlware, and signals.
- ``AxesModelBackend`` was renamed to ``AxesBackend``
  for better naming and preventing the risk of users accidentally
  upgrading without noticing that the APIs have changed.
  Documentation was improved. Exceptions were renamed.
- ``axes.backends.AxesModelBackend.RequestParameterRequired``
  exception was renamed, retyped to ``ValueError`` from ``Exception``, and
  moved to ``axes.exception.AxesBackendRequestParameterRequired``.
- ``AxesBackend`` now raises a
  ``axes.exceptions.AxesBackendPermissionDenied``
  exception when user is locked out which triggers signal handler
  to run on failed logins, checking user lockout statuses.
- Axes lockout signal handler now raises exception
  ``axes.exceptions.AxesSignalPermissionDenied`` on lockouts.
- ``AxesMiddleware`` was added to return lockout responses.
  The middleware handles ``axes.exception.AxesSignalPermissionDenied``.
- ``AXES_USERNAME_CALLABLE`` is now always called with two arguments,
  ``request`` and ``credentials`` instead of ``request``.
