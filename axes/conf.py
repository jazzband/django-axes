from __future__ import unicode_literals

from django.conf import settings
from django.utils.translation import gettext_lazy as _

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

    # use a provided callable to transform the POSTed username into the one used in credentials
    USERNAME_CALLABLE = None

    # only check user name and not location or user_agent
    ONLY_USER_FAILURES = False

    # reset the number of failed attempts after one successful attempt
    RESET_ON_SUCCESS = False

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

    # message to show when locked out and have cooloff enabled
    COOLOFF_MESSAGE = _('Account locked: too many login attempts. Please try again later')

    # message to show when locked out and have cooloff disabled
    PERMALOCK_MESSAGE = _('Account locked: too many login attempts. Contact an admin to unlock your account.')

    # if your deployment is using reverse proxies, set this value to 'left-most' or 'right-most' per your configuration
    PROXY_ORDER = 'left-most'

    # if your deployment is using reverse proxies, set this value to the number of proxies in front of Django
    PROXY_COUNT = None

    # if your deployment is using reverse proxies, set to your trusted proxy IP addresses prefixes if needed
    PROXY_TRUSTED_IPS = None

    # set to the names of request.META attributes that should be checked for the IP address of the client
    # if your deployment is using reverse proxies, ensure that the header attributes are securely set by the proxy
    # ensure that the client can not spoof the headers by setting them and sending them through the proxy
    META_PRECEDENCE_ORDER = getattr(
        settings, 'AXES_META_PRECEDENCE_ORDER', getattr(
            settings, 'IPWARE_META_PRECEDENCE_ORDER', (
                'REMOTE_ADDR',
            )
        )
    )
