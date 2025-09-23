.. _installation:

Installation
============

Axes is easy to install from the PyPI package::

    $ pip install django-axes[ipware]  # use django-ipware for resolving client IP addresses OR
    $ pip install django-axes          # implement and configure custom AXES_CLIENT_IP_CALLABLE

After installing the package, the project settings need to be configured.

**1.** Add ``axes`` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        # Axes app can be in any position in the INSTALLED_APPS list.
        'axes',
    ]

**2.** Add ``axes.backends.AxesStandaloneBackend`` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        # AxesStandaloneBackend should be the first backend in the AUTHENTICATION_BACKENDS list.
        'axes.backends.AxesStandaloneBackend',

        # Django ModelBackend is the default authentication backend.
        'django.contrib.auth.backends.ModelBackend',
    ]

For backwards compatibility, ``AxesBackend`` can be used in place of ``AxesStandaloneBackend``.
The only difference is that ``AxesBackend`` also provides the permissions-checking functionality
of Django's ``ModelBackend`` behind the scenes. We recommend using ``AxesStandaloneBackend``
if you have any custom logic to override Django's standard permissions checks.

**3.** Add ``axes.middleware.AxesMiddleware`` to your list of ``MIDDLEWARE``::

    MIDDLEWARE = [
        # The following is the list of default middleware in new Django projects.
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',

        # AxesMiddleware should be the last middleware in the MIDDLEWARE list.
        # It only formats user lockout messages and renders Axes lockout responses
        # on failed user authentication attempts from login views.
        # If you do not want Axes to override the authentication response
        # you can skip installing the middleware and use your own views.
        # AxesMiddleware runs during the reponse phase. It does not conflict
        # with middleware that runs in the request phase like
        # django.middleware.cache.FetchFromCacheMiddleware.
        'axes.middleware.AxesMiddleware',
    ]

**4.** Run ``python manage.py check`` to check the configuration.

**5.** Run ``python manage.py migrate`` to sync the database.

Axes is now functional with the default settings and is saving user attempts
into your database and locking users out if they exceed the maximum attempts.

You should use the ``python manage.py check`` command to verify the correct configuration in
development, staging, and production environments. It is probably best to use this step as part
of your regular CI workflows to verify that your project is not misconfigured.

Axes uses checks to verify your Django settings configuration for security and functionality.
Many people have different configurations for their development and production environments,
and running the application with misconfigured settings can prevent security features from working.


Version 8 breaking changes and upgrading from django-axes version 7
-------------------------------------------------------------------

Some database related utility functions have moved from ``axes.helpers`` to ``axes.handlers.database`` module and under the ``axes.handlers.database.AxesDatabaseHandler`` class.


Version 7 breaking changes and upgrading from django-axes version 6
-------------------------------------------------------------------

If you use ``settings.AXES_COOLOFF_TIME`` for configuring a callable that returns the cooloff time, it needs to accept at minimum a ``request`` argument of type ``HttpRequest`` from version 7 onwards. Example: ``AXES_COOLOFF_TIME = lambda request: timedelta(hours=2)`` (new call signature) instead of ``AXES_COOLOFF_TIME = lambda: timedelta(hours=2)`` (old cal signature). 

Please see configuration documentation and `jazzband/django-axes#1222 <https://github.com/jazzband/django-axes/pull/1222>`_ for reference.


Version 6 breaking changes and upgrading from django-axes version 5
-------------------------------------------------------------------

If you have not specialized ``django-axes`` configuration in any way
you do not have to update any of the configuration.

The instructions apply to users who have configured ``django-axes`` in their projects
and have used flags that are deprecated. The deprecated flags will be removed in the future
but are compatible for at least version 6.0 of ``django-axes``.

The following flags and configuration have changed:

``django-ipware`` has become an optional dependency.
To keep old behaviour, use ``pip install django-axes[ipware]``
in your install script or use ``django-axes[ipware]``
in your requirements file(s) instead of plain ``django-axes``.
The new ``django-axes`` package does not include ``django-ipware`` by default
but does use ``django-ipware`` if it is installed
and no callables for IP address resolution are configured
with the ``settings.AXES_CLIENT_IP_CALLABLE`` configuration flag.

``django-ipware`` related flags have changed names.
The old flags have been deprecated and will be removed in the future.
To keep old behaviour, rename them in your settings file:

- ``settings.AXES_PROXY_ORDER`` is now ``settings.AXES_IPWARE_PROXY_ORDER``,
- ``settings.AXES_PROXY_COUNT``  is now ``settings.AXES_IPWARE_PROXY_COUNT``,
- ``settings.AXES_PROXY_TRUSTED_IPS`` is now ``settings.AXES_IPWARE_PROXY_TRUSTED_IPS``, and
- ``settings.AXES_META_PRECEDENCE_ORDER`` is now ``settings.AXES_IPWARE_META_PRECEDENCE_ORDER``.

``settings.AXES_LOCKOUT_PARAMETERS`` configuration flag has been added which supersedes the following configuration keys:

#. No configuration for failure tracking in the following items (default behaviour).
#. ``settings.AXES_ONLY_USER_FAILURES``,
#. ``settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``,
#. ``settings.AXES_LOCK_OUT_BY_USER_OR_IP``, and
#. ``settings.AXES_USE_USER_AGENT``.

To keep old behaviour with the new flag, configure the following:

#. If you did not use any flags, use ``settings.AXES_LOCKOUT_PARAMETERS = ["ip_address"]``,
#. If you used ``settings.AXES_ONLY_USER_FAILURES``, use ``settings.AXES_LOCKOUT_PARAMETERS = ["username"]``,
#. If you used ``settings.AXES_LOCK_OUT_BY_USER_OR_IP``, use ``settings.AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]``, and
#. If you used ``settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``, use ``settings.AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]``,
#. If you used ``settings.AXES_USE_USER_AGENT``, add ``"user_agent"`` to your list(s) of lockout parameters.
    #. ``settings.AXES_USE_USER_AGENT`` would become ``settings.AXES_LOCKOUT_PARAMETERS = [["ip_address", "user_agent"]]``
    #. ``settings.AXES_USE_USER_AGENT`` with ``settings.AXES_ONLY_USER_FAILURES`` would become ``settings.AXES_LOCKOUT_PARAMETERS = [["username", "user_agent"]]``
    #. ``settings.AXES_USE_USER_AGENT`` with ``settings.AXES_LOCK_OUT_BY_USER_OR_IP`` would become ``settings.AXES_LOCKOUT_PARAMETERS = [["ip_address", "user_agent"], "username"]``
    #. ``settings.AXES_USE_USER_AGENT`` with ``settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP`` would become ``settings.AXES_LOCKOUT_PARAMETERS = [["ip_address", "user_agent", "username"]]``
    #. Other combinations of flags were previously not considered; the flags had precedence over each other as described in the documentation but were less-than-trivial to understand in their previous form. The new form is more explicit and flexible, although it requires more in-depth configuration.

The new lockout parameters define a combined list of attributes to consider when tracking failed authentication attempts.
They can be any combination of ``username``, ``ip_address`` or ``user_agent`` in a list of strings or list of lists of strings.
The attributes defined in the lists are combined and saved into the database, cache, or other backend for failed logins.
The semantics of the evaluation are available in the documentation and ``axes.helpers.get_client_parameters`` callable.

``settings.AXES_HTTP_RESPONSE_CODE`` default has been changed from ``403`` (Forbidden) to ``429`` (Too Many Requests).
To keep the old behavior, set ``settings.AXES_HTTP_RESPONSE_CODE = 403`` in your settings.

``axes.handlers.base.AxesBaseHandler.is_admin_site`` has been deprecated due to misleading naming
in favour of better-named ``axes.handlers.base.AxesBaseHandler.is_admin_request``.
The old implementation has been kept for backwards compatibility, but will be removed in the future.
The old implementation checked if a request is NOT made for an admin site if ``settings.AXES_ONLY_ADMIN_SITE`` was set.
The new implementation correctly checks if a request is made for an admin site.

``axes.handlers.cache.AxesCacheHandler`` has been updated to use atomic ``cache.incr`` calls
instead of old ``cache.set`` calls in authentication failure tracking
to enable better parallel backend support for atomic cache backends like Redis and Memcached.


Disabling Axes system checks
----------------------------

If you are implementing custom authentication, request middleware, or signal handlers
the Axes checks system might generate false positives in the Django checks framework.

You can silence the unnecessary warnings by using the following Django settings::

   SILENCED_SYSTEM_CHECKS = ['axes.W003']


Axes has the following warnings codes built in:

- ``axes.W001`` for invalid ``CACHES`` configuration.
- ``axes.W002`` for invalid ``MIDDLEWARE`` configuration.
- ``axes.W003`` for invalid ``AUTHENTICATION_BACKENDS`` configuration.
- ``axes.W004`` for deprecated use of ``AXES_*`` setting flags.


.. note::
   Only disable the Axes system checks and warnings if you know what you are doing.
   The default checks are implemented to verify and improve your project's security
   and should only produce necessary warnings due to misconfigured settings.


Disabling Axes components in tests
----------------------------------

If you get errors when running tests, try setting the
``AXES_ENABLED`` flag to ``False`` in your test settings::

    AXES_ENABLED = False

This disables the Axes middleware, authentication backend and signal receivers,
which might fix errors with incompatible test configurations.


Disabling atomic requests
-------------------------

Django offers atomic database transactions that are tied to HTTP requests
and toggled on and off with the ``ATOMIC_REQUESTS`` configuration.

When ``ATOMIC_REQUESTS`` is set to ``True`` Django will always either perform
all database read and write operations in one successful atomic transaction
or in a case of failure roll them back, leaving no trace of the failed
request in the database.

However, sometimes Axes or another plugin can misbehave or not act correctly with
other code, preventing the login mechanisms from working due to e.g. exception
being thrown in some part of the code, preventing access attempts being logged
to database with Axes or causing similar problems.

If new attempts or log objects are not being correctly written to the Axes tables,
it is possible to configure Django ``ATOMIC_REQUESTS`` setting to to ``False``::

    ATOMIC_REQUESTS = False

Please note that atomic requests are usually desirable when writing e.g. RESTful APIs,
but sometimes it can be problematic and warrant a disable.

Before disabling atomic requests or configuring them please read the relevant
Django documentation and make sure you know what you are configuring
rather than just toggling the flag on and off for testing.

Also note that the cache backend can provide correct functionality with
Memcached or Redis caches even with exceptions being thrown in the stack.
