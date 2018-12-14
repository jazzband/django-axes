from __future__ import unicode_literals

from django.utils.translation import gettext_lazy as _

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache'
    }
}

SITE_ID = 1

MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)

AUTHENTICATION_BACKENDS = (
    'axes.backends.AxesModelBackend',
    'django.contrib.auth.backends.ModelBackend',
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

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'axes': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

SECRET_KEY = 'too-secret-for-test'

USE_I18N = False

USE_L10N = False

USE_TZ = False

LOGIN_REDIRECT_URL = '/admin/'

AXES_FAILURE_LIMIT = 10

AXES_FAILURE_LIMIT_MAX_BY_USER = 15

AXES_MESSAGE_CODE_DESC_MAP = {
    1001: _('Attempt {failures_by_user} of {failure_limit_by_user}.'
            ' After invalid attempt {failure_limit_by_user}'
            ' account will be blocked.'),
    1002: _('Attempt {failures_since_start} of {failure_limit}.'
            ' After invalid attempt {failure_limit} account '
            'will be blocked for time {cooloff_time}.'),
    1003: _('On next invalid attempt account'
            ' will be blocked for time {cooloff_time}.'),
    1004: _('Account is temporary blocked for time {cooloff_time}.'),
    1005: _('On next invalid attempt account will be blocked.'),
    1006: _('Account is blocked. Contract admin to unlock account.'),
    1007: _('Account is blocked. (Not in white list).'
            ' Contract admin to unlock account.'),
    1008: _('Account is blocked. (In black list).'
            ' Contract admin to unlock account.'),

    # When blocked by FAILURE_LIMIT but no COOLOFF_TIME
    1009: _('Account is blocked. Contract admin to unlock account.'),
    # When will be blocked by FAILURE_LIMIT but no COOLOFF_TIME
    1010: _('On next invalid attempt account will be blocked.'),
    1011: _('Attempt {failures_since_start} of {failure_limit}.'
            ' After invalid attempt {failure_limit}'
            ' account will be blocked.'),
    }
AXES_MESSAGE_CODE_DESC_MAP = {code: '{}_{}'.format(msg, code) for code, msg in AXES_MESSAGE_CODE_DESC_MAP.items()}


LANGUAGE_CODE = 'en'

LOCALE_ROOT = '/Users/ramilaglyautdinov/workspace/django-axes/axes/locale'
# LOCALE_PATHS =