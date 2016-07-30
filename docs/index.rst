.. Django Axes documentation master file, created by
   sphinx-quickstart on Sat Jul 30 16:37:41 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Django Axes's documentation!
=======================================

Contents:

.. toctree::
   :maxdepth: 2


Installation
============

You can install the latest stable package running this command::

    $ pip install django-axes


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

* ``AXES_LOGIN_FAILURE_LIMIT``: The number of login attempts allowed before a
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
* ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: If ``True`` prevents to login
  from IP under particular user if attempts limit exceed, otherwise lock out
  based on IP.
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_WHITELIST``: If ``True``, users can always login from
  whitelisted IP addresses.
  Default: ``False``
* ``AXES_BEHIND_REVERSE_PROXY``: If ``True``, it will look for the IP address from the header defined at ``AXES_REVERSE_PROXY_HEADER``. Please make sure if you enable this setting to configure your proxy to set the correct value for the header, otherwise you could be attacked by setting this header directly in every request.
  Default: ``False``
* ``AXES_REVERSE_PROXY_HEADER``: If ``AXES_BEHIND_REVERSE_PROXY`` is ``True``, it will look for the IP address from this header.
  Default: ``HTTP_X_FORWARDED_FOR``


Usage
=====

Using ``django-axes`` is extremely simple. All you need to do is periodically
check the Access Attempts section of the admin.

By default, django-axes will lock out repeated attempts from the same IP
address. You can allow this IP to attempt again by deleting the relevant
``AccessAttempt`` records in the admin.

You can also use the ``axes_reset`` management command using Django's
``manage.py``.

* ``manage.py axes_reset`` will reset all lockouts and access records.
* ``manage.py axes_reset ip`` will clear lockout/records for ip

In your code, you can use ``from axes.utils import reset``.

* ``reset()`` will reset all lockouts and access records.
* ``reset(ip=ip)`` will clear lockout/records for ip
* ``reset(username=username)`` will clear lockout/records for a username



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

