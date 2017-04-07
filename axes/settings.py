from datetime import timedelta

from django.conf import settings

# see if the user has overridden the failure limit
FAILURE_LIMIT = getattr(settings, 'AXES_LOGIN_FAILURE_LIMIT', 3)

# see if the user has set axes to lock out logins after failure limit
LOCK_OUT_AT_FAILURE = getattr(settings, 'AXES_LOCK_OUT_AT_FAILURE', True)

USE_USER_AGENT = getattr(settings, 'AXES_USE_USER_AGENT', False)

# use a specific username field to retrieve from login POST data
USERNAME_FORM_FIELD = getattr(settings, 'AXES_USERNAME_FORM_FIELD', 'username')

# use a specific password field to retrieve from login POST data
PASSWORD_FORM_FIELD = getattr(settings, 'AXES_PASSWORD_FORM_FIELD', 'password')

# only check user name and not location or user_agent
AXES_ONLY_USER_FAILURES = getattr(settings, 'AXES_ONLY_USER_FAILURES', False)

# see if the django app is sitting behind a reverse proxy
BEHIND_REVERSE_PROXY = getattr(settings, 'AXES_BEHIND_REVERSE_PROXY', False)

# if we are behind a proxy, we need to know how many proxies there are
NUM_PROXIES = getattr(settings, 'AXES_NUM_PROXIES', 0)

# if the django app is behind a reverse proxy, look for the ip address using this HTTP header value
REVERSE_PROXY_HEADER = \
    getattr(settings, 'AXES_REVERSE_PROXY_HEADER', 'HTTP_X_FORWARDED_FOR')

# lock out user from particular IP based on combination USER+IP
LOCK_OUT_BY_COMBINATION_USER_AND_IP = \
    getattr(settings, 'AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP', False)

COOLOFF_TIME = getattr(settings, 'AXES_COOLOFF_TIME', None)
if (isinstance(COOLOFF_TIME, int) or isinstance(COOLOFF_TIME, float)):
    COOLOFF_TIME = timedelta(hours=COOLOFF_TIME)

DISABLE_ACCESS_LOG = getattr(settings, 'AXES_DISABLE_ACCESS_LOG', False)

DISABLE_SUCCESS_ACCESS_LOG = getattr(settings, 'AXES_DISABLE_SUCCESS_ACCESS_LOG', False)

LOGGER = getattr(settings, 'AXES_LOGGER', 'axes.watch_login')

LOCKOUT_TEMPLATE = getattr(settings, 'AXES_LOCKOUT_TEMPLATE', None)

LOCKOUT_URL = getattr(settings, 'AXES_LOCKOUT_URL', None)

VERBOSE = getattr(settings, 'AXES_VERBOSE', True)

# whitelist and blacklist
# TODO: convert the strings to IPv4 on startup to avoid type conversion during processing
NEVER_LOCKOUT_WHITELIST = \
    getattr(settings, 'AXES_NEVER_LOCKOUT_WHITELIST', False)

ONLY_WHITELIST = getattr(settings, 'AXES_ONLY_ALLOW_WHITELIST', False)

IP_WHITELIST = getattr(settings, 'AXES_IP_WHITELIST', None)

IP_BLACKLIST = getattr(settings, 'AXES_IP_BLACKLIST', None)
