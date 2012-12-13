``django-axes`` is a very simple way for you to keep track of failed login
attempts, both for the Django admin and for the rest of your site.  The name is
sort of a geeky pun, since ``axes`` can be read interpreted as:

  * "access", as in monitoring access attempts
  * "axes", as in tools you can use hack (generally on wood).  In this case,
    however, the "hacking" part of it can be taken a bit further: ``django-axes``
    is intended to help you *stop* people from hacking (popular media
    definition) your website.  Hilarious, right?  That's what I thought too!

Requirements
============

``django-axes`` requires Django 1.0 or later.  The application is intended to
work around the Django admin and the regular ``django.contrib.auth``
login-powered pages.

Installation
============

Download ``django-axes`` using **one** of the following methods:

easy_install
------------

You can download the package from the `CheeseShop <http://pypi.python.org/pypi/django-axes/>`_ or use::

    easy_install django-axes

to download and install ``django-axes``.

Package Download
----------------

Download the latest ``.tar.gz`` file from the downloads section and extract it
somewhere you'll remember.  Use ``python setup.py install`` to install it.

Checkout from GitHub
--------------------

Execute the following command, and make sure you're checking ``django-axes``
out somewhere on the ``PYTHONPATH``::

    git clone git://github.com/codekoala/django-axes.git

Verifying Installation
----------------------

The easiest way to ensure that you have successfully installed ``django-axes``
is to execute a command such as::

    python -c "import axes; print axes.get_version()"

If that command completes with some sort of version number, you're probably
good to go.  If you see error output, you need to check your installation (I'd
start with your ``PYTHONPATH``).

Configuration
=============

First of all, you must add this project to your list of ``INSTALLED_APPS`` in
``settings.py``::

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

Next, install the ``FailedLoginMiddleware`` middleware::

    MIDDLEWARE_CLASSES = (
        'django.middleware.common.CommonMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'axes.middleware.FailedLoginMiddleware'
    )

Finally, if you're using Django's @staff_member_required, you'll want to start
importing this from axes rather than from Django::

    from axes.decorators import staff_member_required

Run ``manage.py syncdb``.  This creates the appropriate tables in your database
that are necessary for operation.

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

Usage
=====

Using ``django-axes`` is extremely simple.  Once you install the application
and the middleware, all you need to do is periodically check the Access
Attempts section of the admin.  A log file is also created for you to keep
track of the events surrounding failed login attempts.  This log file can be
found in your Django project directory, by the name of ``axes.log``.  In the
future I plan on offering a way to customize options for logging a bit more.

By default, django-axes will lock out repeated attempts from the same IP
address.  You can allow this IP to attempt again by deleting the relevant
``AccessAttempt`` records in the admin.

You can also use the ``axes_reset`` management command (since 1.2.5-rc1). Using Django's
``manage.py``.

* ``manage.py axes_reset`` will reset all lockouts and access records.
* ``manage.py axes_reset ip`` will clear lockout/records for ip

In your code, you can use ``from axes.utils import reset``.

* ``reset()`` will reset all lockouts and access records.
* ``reset(ip)`` will clear lockout/records for ip

``reset`` will print a message to std out if there is nothing to reset,
unless called with ``silent = True``
