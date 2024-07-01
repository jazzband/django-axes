
django-axes
===========

.. image:: https://jazzband.co/static/img/badge.svg
   :target: https://jazzband.co/
   :alt: Jazzband

.. image:: https://img.shields.io/github/stars/jazzband/django-axes.svg?label=Stars&style=socialcA
   :target: https://github.com/jazzband/django-axes
   :alt: GitHub

.. image:: https://img.shields.io/pypi/v/django-axes.svg
   :target: https://pypi.org/project/django-axes/
   :alt: PyPI release

.. image:: https://img.shields.io/pypi/pyversions/django-axes.svg
   :target: https://pypi.org/project/django-axes/
   :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/djversions/django-axes.svg
   :target: https://pypi.org/project/django-axes/
   :alt: Supported Django versions

.. image:: https://img.shields.io/readthedocs/django-axes.svg
   :target: https://django-axes.readthedocs.io/
   :alt: Documentation

.. image:: https://github.com/jazzband/django-axes/workflows/Test/badge.svg
   :target: https://github.com/jazzband/django-axes/actions
   :alt: GitHub Actions

.. image:: https://codecov.io/gh/jazzband/django-axes/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jazzband/django-axes
   :alt: Coverage


Axes is a Django plugin for keeping track of suspicious
login attempts for your Django based website
and implementing simple brute-force attack blocking.

The name is sort of a geeky pun, since it can be interpreted as:

* ``access``, as in monitoring access attempts, or
* ``axes``, as in tools you can use to hack (generally on wood).


Functionality
-------------

Axes records login attempts to your Django powered site and prevents attackers
from attempting further logins to your site when they exceed the configured attempt limit.

Axes can track the attempts and persist them in the database indefinitely,
or alternatively use a fast and DDoS resistant cache implementation.

Axes can be configured to monitor login attempts by
IP address, username, user agent, or their combinations.

Axes supports cool off periods, IP address allow listing and block listing,
user account allow listing, and other features for Django access management.


Documentation
-------------

For more information on installation and configuration see the documentation at:

https://django-axes.readthedocs.io/


Issues
------

If you have questions or have trouble using the app please file a bug report at:

https://github.com/jazzband/django-axes/issues


Contributing
------------

See `CONTRIBUTING <CONTRIBUTING.rst>`__.
