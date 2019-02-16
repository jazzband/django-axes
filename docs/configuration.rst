.. _configuration:

Configuration
=============

Add ``axes`` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        # ... other applications per your preference.

        'axes',
    ]

Add ``axes.backends.AxesBackend`` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        # AxesBackend should be the first backend in the list.
        # It stops the authentication flow when a user is locked out.
        'axes.backends.AxesBackend',

        # ... other authentication backends per your preference.

        # Django ModelBackend is the default authentication backend.
        'django.contrib.auth.backends.ModelBackend',
    ]

Add ``axes.middleware.AxesMiddleware`` to your list of ``MIDDLEWARE``::

    MIDDLEWARE = [
        # The following is the list of default middleware in new Django projects.
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',

        # ... other middleware per your preference.

        # AxesMiddleware should be the last middleware in the list.
        # It pretty formats authentication errors into readable responses.
        'axes.middleware.AxesMiddleware',
    ]

Run ``python manage.py migrate`` to sync the database.

How does Axes function?
-----------------------

When a user tries to log in in Django, the login is usually performed
by running a number of authentication backends that check user login
information by calling the ``django.contrib.auth.authenticate`` function.

If an authentication backend does not approve of a user login,
it can raise a ``django.core.exceptions.PermissionDenied`` exception.

If a login fails, Django then fires a
``from django.contrib.auth.signals.user_login_failed`` signal.

If this signal raises an exception, it is propagated through the
Django middleware stack where it can be caught, or alternatively
where it can bubble up to the default Django exception handlers.

A normal login flow for Django runs as follows::

    1. Django or plugin login view is called by
       for example user sending form data with browser.

    2. django.contrib.auth.authenticate is called by
       the view code to check the authentication request
       for user and return a user object matching it.

    3. AUTHENTICATION_BACKENDS are iterated over
       and their authenticate methods called one-by-one.

    4. An authentication backend either returns
       a user object which results in that user
       being logged in or returns None.
       If a PermissionDenied error is raised
       by any of the authentication backends
       the whole request authentication flow
       is aborted and signal handlers triggered.

Axes monitors logins with the ``user_login_failed`` signal handler
and after login attempts exceed the given maximum, starts blocking them.

The blocking is done by ``AxesBackend`` which checks every request
coming through the Django authentication flow and verifies they
are not blocked, and allows the requests to go through if the check passes.

If any of the checks fails, an exception is raised which interrupts
the login process and triggers the Django login failed signal handlers.

Another exception is raised by a Axes signal handler, which is
then caught by ``AxesMiddleware`` and converted into a readable
error because the user is currently locked out of the system.

Axes implements the lockout flow as follows::

    1. Django or plugin login view is called.

    2. django.contrib.auth.authenticate is called.

    3. AUTHENTICATION_BACKENDS are iterated over
       where axes.backends.AxesBackend is the first.

    4. AxesBackend checks authentication request
       for lockouts rules and either aborts the
       authentication flow or lets the authentication
       process proceed to the next
       configured authentication backend.

    [The lockout happens at this stage if appropriate]

    5. User is locked out and signal handlers
       are notified of the failed login attempt.

    6. axes.signals.log_user_login_failed runs
       and raises a AxesSignalPermissionDenied
       exception that bubbles up the middleware stack.

    7. AxesMiddleware processes the exception
       and returns a readable error to the user.

This plugin assumes that the login views either call
the django.contrib.auth.authenticate method to log in users
or otherwise take care of notifying Axes of authentication
attempts or login failures the same way Django does.

The login flows can be customized and the Axes
authentication backend or middleware can be easily swapped.

Running checks
--------------

Use the ``python manage.py check`` command to verify the correct configuration in both
development and production environments. It is probably best to use this step as part
of your regular CI workflows to verify that your project is not misconfigured.

Axes uses the checks to verify your cache configuration to see that your caches
should be functional with the configuration of Axes. Many people have different configurations
for their development and production environments.


Known configuration problems
----------------------------

Axes has a few configuration issues with external packages and specific cache backends
due to their internal implementations.

Cache problems
~~~~~~~~~~~~~~

If you are running Axes on a deployment with in-memory Django cache,
the ``axes_reset`` functionality might not work predictably.

Axes caches access attempts application-wide, and the in-memory cache
only caches access attempts per Django process, so for example
resets made in one web server process or the command line with ``axes_reset``
might not remove lock-outs that are in the sepate process' in-memory cache
such as the web server process serving your login or admin page.

To circumvent this problem please use somethings else than
``django.core.cache.backends.locmem.LocMemCache`` as your
cache backend in Django cache ``BACKEND`` setting.

If it is not an option to change the default cache you can add a cache
specifically for use with Axes. This is a two step process. First you need to
add an extra cache to ``CACHES`` with a name of your choice::

    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        },
        'axes_cache': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        }
    }

The next step is to tell Axes to use this cache through adding ``AXES_CACHE``
to your ``settings.py`` file::

    AXES_CACHE = 'axes_cache'

There are no known problems in other cache backends such as
``DummyCache``, ``FileBasedCache``, or ``MemcachedCache`` backends.

Authentication backend problems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you get ``AxesBackendRequestParameterRequired`` exceptions,
make sure any auth libraries and middleware you use pass the request object to authenticate.
Notably in older versions of Django Rest Framework (DRF) (before 3.7.0), ``BasicAuthentication`` does not pass request.
`Here is an example workaround for DRF <https://gist.github.com/markddavidoff/7e442b1ea2a2e68d390e76731c35afe7>`_.

Reverse proxy configuration
---------------------------

Django Axes makes use of ``django-ipware`` package to detect the IP address of the client
and uses some conservative configuration parameters by default for security.

If you are using reverse proxies, you will need to configure one or more of the
following settings to suit your set up to correctly resolve client IP addresses:

* ``AXES_PROXY_COUNT``: The number of reverse proxies in front of Django as an integer. Default: ``None``
* ``AXES_META_PRECEDENCE_ORDER``: The names of ``request.META`` attributes as a tuple of strings
  to check to get the client IP address. Check the Django documentation for header naming conventions.
  Default: ``IPWARE_META_PRECEDENCE_ORDER`` setting if set, else ``('REMOTE_ADDR', )``

Customizing Axes
----------------

You have a couple options available to you to customize ``django-axes`` a bit.
These should be defined in your ``settings.py`` file.

* ``AXES_CACHE``: The name of the cache for Axes to use.
  Default: ``'default'``
* ``AXES_FAILURE_LIMIT``: The number of login attempts allowed before a
  record is created for the failed logins.  Default: ``3``
* ``AXES_LOCK_OUT_AT_FAILURE``: After the number of allowed login attempts
  are exceeded, should we lock out this IP (and optional user agent)?
  Default: ``True``
* ``AXES_USE_USER_AGENT``: If ``True``, lock out / log based on an IP address
  AND a user agent.  This means requests from different user agents but from
  the same IP are treated differently.  Default: ``False``
* ``AXES_COOLOFF_TIME``: If set, defines a period of inactivity after which
  old failed login attempts will be forgotten. Can be set to a python
  timedelta object or an integer. If an integer, will be interpreted as a
  number of hours.  Default: ``None``
* ``AXES_HANDLER``: If set, overrides the default signal handler backend.
  Default: ``'axes.handlers.AxesHandler'``
* ``AXES_LOGGER``: If set, specifies a logging mechanism for Axes to use.
  Default: ``'axes.watch_login'``
* ``AXES_LOCKOUT_TEMPLATE``: If set, specifies a template to render when a
  user is locked out. Template receives cooloff_time and failure_limit as
  context variables. Default: ``None``
* ``AXES_LOCKOUT_URL``: If set, specifies a URL to redirect to on lockout. If
  both AXES_LOCKOUT_TEMPLATE and AXES_LOCKOUT_URL are set, the template will
  be used. Default: ``None``
* ``AXES_VERBOSE``: If ``True``, you'll see slightly more logging for Axes.
  Default: ``True``
* ``AXES_USERNAME_FORM_FIELD``: the name of the form field that contains your
  users usernames. Default: ``username``
* ``AXES_USERNAME_CALLABLE``: A callable or a string path to function that takes
  two arguments for user lookups: ``def get_username(request: HttpRequest, credentials: dict) -> str: ...``.
  This can be any callable such as ``AXES_USERNAME_CALLABLE = lambda request, credentials: 'username'``
  or a full Python module path to callable such as ``AXES_USERNAME_CALLABLE = 'example.get_username``.
  The ``request`` is a HttpRequest like object and the ``credentials`` is a dictionary like object.
  ``credentials`` are the ones that were passed to Django ``authenticate()`` in the login flow.
  If no function is supplied, Axes fetches the username from the ``credentials`` or ``request.POST``
  dictionaries based on ``AXES_USERNAME_FORM_FIELD``. Default: ``None``
* ``AXES_PASSWORD_FORM_FIELD``: the name of the form or credentials field that contains your
  users password. Default: ``password``
* ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: If ``True`` prevents the login
  from IP under a particular user if the attempt limit has been exceeded,
  otherwise lock out based on IP.
  Default: ``False``
* ``AXES_ONLY_USER_FAILURES`` : If ``True`` only locks based on user id and never locks by IP
  if attempts limit exceed, otherwise utilize the existing IP and user locking logic
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_GET``: If ``True``, Axes will never lock out HTTP GET requests.
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_WHITELIST``: If ``True``, users can always login from whitelisted IP addresses.
  Default: ``False``
* ``AXES_CLIENT_IP_ATTRIBUTE``: A string that is used to lookup and set client IP on the request object. Default: ``'axes_client_ip'``
* ``AXES_IP_BLACKLIST``: An iterable of IPs to be blacklisted. For example: ``AXES_IP_BLACKLIST = ['0.0.0.0']``. Default: ``None``
* ``AXES_IP_WHITELIST``: An iterable of IPs to be whitelisted. For example: ``AXES_IP_WHITELIST = ['0.0.0.0']``. Default: ``None``
* ``AXES_DISABLE_ACCESS_LOG``: If ``True``, disable all access logging, so the admin interface will be empty. Default: ``False``
* ``AXES_DISABLE_SUCCESS_ACCESS_LOG``: If ``True``, successful logins will not be logged, so the access log shown in the admin interface will only list unsuccessful login attempts. Default: ``False``
* ``AXES_RESET_ON_SUCCESS``: If ``True``, a successful login will reset the number of failed logins. Default: ``False``
