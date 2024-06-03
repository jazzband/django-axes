DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

CACHES = {
    "default": {
        # This cache backend is OK to use in development and testing
        # but has the potential to break production setups with more than on process
        # due to each process having their own local memory based cache
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache"
    }
}

SITE_ID = 1

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "axes.middleware.AxesMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# Use MD5 for tests as it is considerably faster than other options
# note that this should never be used in any online setting
# where users actually log in to the system due to easy exploitability
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

ROOT_URLCONF = "tests.urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.admin",
    "axes",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"axes": {"handlers": ["console"], "level": "INFO", "propagate": False}},
}

SECRET_KEY = "too-secret-for-test"

USE_I18N = False

USE_TZ = False

LOGIN_REDIRECT_URL = "/admin/"

AXES_FAILURE_LIMIT = 10

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
