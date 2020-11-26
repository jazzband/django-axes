
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

All contributions are welcome!

It is best to separate proposed changes and PRs into small, distinct patches
by type so that they can be merged faster into upstream and released quicker.

One way to organize contributions would be to separate PRs for e.g.

* bugfixes,
* new features,
* code and design improvements,
* documentation improvements, or
* tooling and CI improvements.

Merging contributions requires passing the checks configured
with the CI. This includes running tests and linters successfully
on the currently officially supported Python and Django versions.

The test automation is run automatically with GitHub Actions, but you can
run it locally with the ``tox`` command before pushing commits.

Please note that this is a `Jazzband <https://jazzband.co>`_ project.
By contributing you agree to abide by the
`Contributor Code of Conduct <https://jazzband.co/about/conduct>`_
and follow the `guidelines <https://jazzband.co/about/guidelines>`_.
