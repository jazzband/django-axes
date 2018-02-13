from django.conf import settings

from appconf import AppConf


class MyAppConf(AppConf):
    # see if the user has overridden the failure limit
    FAILURE_LIMIT = 3

    # see if the user has set axes to lock out logins after failure limit
    LOCK_OUT_AT_FAILURE = True

    USE_USER_AGENT = False

    # use a specific username field to retrieve from login POST data
    USERNAME_FORM_FIELD = 'username'

    # use a specific password field to retrieve from login POST data
    PASSWORD_FORM_FIELD = 'password'

    # only check user name and not location or user_agent
    ONLY_USER_FAILURES = False

    # lock out user from particular IP based on combination USER+IP
    LOCK_OUT_BY_COMBINATION_USER_AND_IP = False

    DISABLE_ACCESS_LOG = False

    DISABLE_SUCCESS_ACCESS_LOG = False

    LOGGER = 'axes.watch_login'

    LOCKOUT_TEMPLATE = None

    LOCKOUT_URL = None

    COOLOFF_TIME = None

    VERBOSE = True

    # whitelist and blacklist
    # TODO: convert the strings to IPv4 on startup to avoid type conversion during processing
    NEVER_LOCKOUT_WHITELIST = False

    ONLY_WHITELIST = False

    IP_WHITELIST = None

    IP_BLACKLIST = None
