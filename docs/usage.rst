.. _usage:

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

