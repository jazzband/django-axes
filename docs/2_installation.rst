.. _installation:

2. Installation
===============

Axes is easy to install from the PyPI package::

    $ pip install django-axes

After installing the package, the project settings need to be configured.

**1.** Add ``axes`` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        # Axes app can be in any position in the INSTALLED_APPS list.
        'axes',
    ]

**2.** Add ``axes.backends.AxesBackend`` to the top of ``AUTHENTICATION_BACKENDS``::

    AUTHENTICATION_BACKENDS = [
        # AxesBackend should be the first backend in the AUTHENTICATION_BACKENDS list.
        'axes.backends.AxesBackend',

        # Django ModelBackend is the default authentication backend.
        'django.contrib.auth.backends.ModelBackend',
    ]

**3.** Add ``axes.middleware.AxesMiddleware`` to your list of ``MIDDLEWARE``::

    MIDDLEWARE = [
        # The following is the list of default middleware in new Django projects.
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',

        # AxesMiddleware should be the last middleware in the MIDDLEWARE list.
        'axes.middleware.AxesMiddleware',
    ]

**4.** Run ``python manage.py check`` to check the configuration.

**5.** Run ``python manage.py migrate`` to sync the database.

Axes is now functional with the default settings and is saving user attempts
into your database and locking users out if they exceed the maximum attempts.

You should use the ``python manage.py check`` command to verify the correct configuration in both
development, staging, and production environments. It is probably best to use this step as part
of your regular CI workflows to verify that your project is not misconfigured.

Axes uses checks to verify your Django settings configuration for security and functionality.
Many people have different configurations for their development and production environments,
and running the application with misconfigured settings can prevent security features from working.
