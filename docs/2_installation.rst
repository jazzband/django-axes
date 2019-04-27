.. _installation:

2. Installation
===============

Axes is easy to install from the PyPI package::

    $ pip install django-axes


Configuring settings
--------------------

After installing the package, the project ``settings.py`` needs to be configured.

1. add ``axes`` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        # ... other applications per your preference.

        'axes',
    ]

2. add ``axes.backends.AxesBackend`` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        # AxesBackend should be the first backend in the list.
        # It stops the authentication flow when a user is locked out.
        'axes.backends.AxesBackend',

        # ... other authentication backends per your preference.

        # Django ModelBackend is the default authentication backend.
        'django.contrib.auth.backends.ModelBackend',
    ]

3. add ``axes.middleware.AxesMiddleware`` to your list of ``MIDDLEWARE``::

    MIDDLEWARE = [
        # The following is the list of default middleware in new Django projects.
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',

        # ... other middleware per your preference.

        # AxesMiddleware should be the last middleware in the list.
        # It pretty formats authentication errors into readable responses.
        'axes.middleware.AxesMiddleware',
    ]

4. Run ``python manage.py migrate`` to sync the database.

Axes is now functional with the default settings and is saving user attempts
into your database and locking users out if they exceed the maximum attempts.


Running Django system checks
----------------------------

Use the ``python manage.py check`` command to verify the correct configuration in both
development and production environments. It is probably best to use this step as part
of your regular CI workflows to verify that your project is not misconfigured.

Axes uses the checks to verify your cache configuration to see that your caches
should be functional with the configuration of Axes. Many people have different configurations
for their development and production environments.