.. image:: https://jazzband.co/static/img/jazzband.svg
   :target: https://jazzband.co/
   :alt: Jazzband

This is a `Jazzband <https://jazzband.co>`_ project. By contributing you agree to abide by the `Contributor Code of Conduct <https://jazzband.co/about/conduct>`_ and follow the `guidelines <https://jazzband.co/about/guidelines>`_.


Contributions
=============

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


Development
===========

You can contribute to this project forking it from GitHub and sending pull requests.

First `fork <https://help.github.com/en/articles/fork-a-repo>`_ the
`repository <https://github.com/jazzband/django-axes>`_ and then clone it::

    $ git clone git@github.com:<you>/django-axes.git

Initialize a virtual environment for development purposes::

    $ mkdir -p ~/.virtualenvs
    $ python3 -m venv ~/.virtualenvs/django-axes
    $ source ~/.virtualenvs/django-axes/bin/activate

Then install the necessary requirements::

    $ cd django-axes
    $ pip install -r requirements.txt

Unit tests are located in the ``axes/tests`` folder and can be easily run with the pytest tool::

    $ pytest

Prospector runs a number of source code style, safety, and complexity checks::

    $ prospector

Mypy runs static typing checks to verify the source code type annotations and correctness::

    $ mypy .

Before committing, you can run all the above tests against all supported Python and Django versions with tox::

    $ tox

Tox runs the same test set that is run by GitHub Actions, and your code should be good to go if it passes.

If you wish to limit the testing to specific environment(s), you can parametrize the tox run::

    $ tox -e py39-django32

After you have pushed your changes, open a pull request on GitHub for getting your code upstreamed.
