from datetime import timedelta

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

SITE_ID = 1

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.FailedLoginMiddleware'
)

ROOT_URLCONF = 'axes.test_urls'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.admin',

    'axes',
)

SECRET_KEY = 'too-secret-for-test'

LOGIN_REDIRECT_URL = '/admin/'

AXES_LOGIN_FAILURE_LIMIT = 10
AXES_COOLOFF_TIME = timedelta(seconds=2)
