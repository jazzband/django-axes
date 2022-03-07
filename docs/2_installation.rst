.. _installation:

Installation
============

Axes is easy to install from the PyPI package::

    $ pip install django-axes

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

**2.** Add ``axes.backends.AxesBackend`` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        # AxesBackend should be the first backend in the AUTHENTICATION_BACKENDS list.
        'axes.backends.AxesBackend',

        # Django ModelBackend is the default authentication backend.
        'django.contrib.auth.backends.ModelBackend',
    ]

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
