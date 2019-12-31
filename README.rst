
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

.. image:: https://img.shields.io/readthedocs/django-axes.svg
   :target: https://django-axes.readthedocs.io/
   :alt: Documentation

.. image:: https://secure.travis-ci.org/jazzband/django-axes.svg?branch=master
   :target: http://travis-ci.org/jazzband/django-axes
   :alt: Build Status

.. image:: https://codecov.io/gh/jazzband/django-axes/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jazzband/django-axes
   :alt: Coverage


Axes is a very simple way for you to keep track of failed
login attempts for your login and administration views.

The name is sort of a geeky pun, since it can be interpreted as:

* ``access``, as in monitoring access attempts, or
* ``axes``, as in tools you can use to hack (generally on wood).

In this case, however, the hacking part of it can be taken a bit further:
**Axes is intended to help you stop people from brute forcing Django views**.


Functionality
-------------

Axes records login attempts to your Django powered site and prevents attackers
from brute forcing the site when they exceed the configured attempt limit.

Axes can track the attempts and persist them in the database indefinitely,
or alternatively use a fast and DDoS resistant cache implementation.

Axes can be configured to monitor login attempts by
IP address, username, user agent, or their combinations.

Axes supports cool off periods, IP address whitelisting and blacklisting,
user account whitelisting, and other features for Django access management.


Documentation
-------------

For more information on installation and configuration see the documentation at:

https://django-axes.readthedocs.io/


Issues
------

If you have questions or have trouble using the app please file a bug report at:

https://github.com/jazzband/django-axes/issues


Contributions
-------------

This is a `Jazzband <https://jazzband.co>`_ project.
By contributing you agree to abide by the
`Contributor Code of Conduct <https://jazzband.co/about/conduct>`_
and follow the `guidelines <https://jazzband.co/about/guidelines>`_.

It is best to separate proposed changes and PRs into small, distinct patches
by type so that they can be merged faster into upstream and released quicker:

* features,
* bugfixes,
* code style improvements, and
* documentation improvements.

All contributions are required to pass the quality gates configured
with the CI. This includes running tests and linters successfully
on the currently officially supported Python and Django versions.

The test automation is run automatically by Travis CI, but you can
run it locally with the ``tox`` command before pushing commits.
