.. _development:

9. Development
==============

You can contribute to this project forking it from GitHub and sending pull requests.


Setting up a development environment
------------------------------------

Fork and clone the repository, initialize a virtual environment and install the requirements::

    $ git clone git@github.com:<fork>/django-axes.git
    $ cd django-axes
    $ mkdir ~/.virtualenvs
    $ python3 -m venv ~/.virtualenvs/django-axes
    $ source ~/.virtualenvs/bin/activate
    $ pip install -r requirements.txt

Unit tests that are in the `axes/tests` folder can be run easily with the ``axes.tests.settings`` configuration::

    $ pytest

Prospector runs a number of source code style, safety, and complexity checks::

    $ prospector

Mypy runs static typing checks to verify the source code type annotations and correctness::

    $ mypy .

Before committing, you can run all the tests against all supported Django versions with tox::

    $ tox

Tox runs the same tests that are run by Travis, and your code should be good to go if it passes.

After you have made your changes, open a pull request on GitHub for getting your code upstreamed.
