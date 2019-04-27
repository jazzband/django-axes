.. _usage:

3. Usage
========

Once Axes is is installed and configured, you can login and logout
of your application via the ``django.contrib.auth`` views.
The attempts will be logged and visible in the Access Attempts section in admin.

By default, Axes will lock out repeated access attempts from the same IP address.
You can allow this IP to attempt again by deleting relevant AccessAttempt records.

Records can be deleted, for example, by using the Django admin application.

You can also use the ``axes_reset``, ``axes_reset_ip``, and ``axes_reset_username``
management commands with the Django ``manage.py`` command helpers:

- ``python manage.py axes_reset``
  will reset all lockouts and access records.
- ``python manage.py axes_reset_ip [ip ...]``
  will clear lockouts and records for the given IP addresses.
- ``python manage.py axes_reset_username [username ...]``
  will clear lockouts and records for the given usernames.

In your code, you can use the ``axes.utils.reset`` function.

- ``reset()`` will reset all lockouts and access records.
- ``reset(ip=ip)`` will clear lockouts and records for the given IP address.
- ``reset(username=username)`` will clear lockouts and records for the given username.

Please note that if you give both ``username`` and ``ip`` arguments to ``reset``
that attempts that have both the set IP and username are reset.

The effective behaviour of ``reset`` is to ``and`` the terms instead of ``or``ing them.
