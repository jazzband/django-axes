.. _configuration:

Configuration
=============

Add `axes` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = (
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.sites',
        ...
        'axes',
        ...
    )

Run ``python manage.py migrate`` to sync the database.

Configure `django-ipware <https://github.com/un33k/django-ipware/>`_ to your liking. Pay close attention to the  `IPWARE_META_PRECEDENCE_ORDER <https://github.com/un33k/django-ipware#precedence-order>`_ setting. Please note that this configuration is required for functional security in your project. A good staarting point for a project running without a reverse proxy could be::

    IPWARE_META_PRECEDENCE_ORDER = (
        'REMOTE_ADDR',
    )

Add `axes.middleware.DjangoAxesAuthBackend` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        'axes.middleware.DjangoAxesAuthBackend',
        ...
        'django.contrib.auth.backends.ModelBackend',
        ...
    ]

Things to you might need to change in your code, especially if you get a ``AxesModelBackend.RequestParameterRequired``:

- make sure any calls to ``django.contrib.auth.authenticate`` pass the request.
- make sure any auth libraries you use that call the authentication middleware stack pass request. Notably Django Rest
  Framework (DRF) ``BasicAuthentication`` does not pass request. `Here is an example workaround for DRF`_.

.. _Here is an example workaround for DRF: https://gist.github.com/markddavidoff/7e442b1ea2a2e68d390e76731c35afe7

Known configuration problems
----------------------------

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

The next step is to tell axes to use this cache through adding ``AXES_CACHE``
to your ``settings.py`` file::

    AXES_CACHE = 'axes_cache'

There are no known problems in other cache backends such as
``DummyCache``, ``FileBasedCache``, or ``MemcachedCache`` backends.

Customizing Axes
----------------

You have a couple options available to you to customize ``django-axes`` a bit.
These should be defined in your ``settings.py`` file.

* ``AXES_CACHE``: The name of the cache for axes to use.
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
* ``AXES_LOGGER``: If set, specifies a logging mechanism for axes to use.
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
* ``AXES_PASSWORD_FORM_FIELD``: the name of the form field that contains your
  users password. Default: ``password``
* ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: If ``True`` prevents the login
  from IP under a particular user if the attempt limit has been exceeded,
  otherwise lock out based on IP.
  Default: ``False``
* ``AXES_ONLY_USER_FAILURES`` : If ``True`` only locks based on user id and never locks by IP
  if attempts limit exceed, otherwise utilize the existing IP and user locking logic
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_WHITELIST``: If ``True``, users can always login from whitelisted IP addresses.
  Default: ``False``
* ``AXES_IP_WHITELIST``: A list of IP's to be whitelisted. For example: AXES_IP_WHITELIST=['0.0.0.0']. Default: []
  Default: ``False``
* ``AXES_DISABLE_ACCESS_LOG``: If ``True``, disable all access logging, so the admin interface will be empty. Default: ``False``
* ``AXES_DISABLE_SUCCESS_ACCESS_LOG``: If ``True``, successful logins will not be logged, so the access log shown in the admin interface will only list unsuccessful login attempts. Default: ``False``
