.. _development:

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

    $ tox -e py39-django22

After you have pushed your changes, open a pull request on GitHub for getting your code upstreamed.
