.. _configuration:

Configuration
=============

Just add `axes` to your ``INSTALLED_APPS``::

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

Remember to run ``python manage.py migrate`` to sync the database.


Customizing Axes
----------------

You have a couple options available to you to customize ``django-axes`` a bit.
These should be defined in your ``settings.py`` file.

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
