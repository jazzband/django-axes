from django.conf import settings
from django.utils.translation import gettext_lazy as _

from appconf import AppConf


class AxesAppConf(AppConf):
    # disable plugin when set to False
    ENABLED = True

    # see if the user has overridden the failure limit
    FAILURE_LIMIT = 3

    # see if the user has set axes to lock out logins after failure limit
    LOCK_OUT_AT_FAILURE = True

    # lock out with the combination of username and IP address
    LOCK_OUT_BY_COMBINATION_USER_AND_IP = False

    # lock out with username and never the IP or user agent
    ONLY_USER_FAILURES = False

    # lock out just for admin site
    ONLY_ADMIN_SITE = False

    # show Axes logs in admin
    ENABLE_ADMIN = True

    # lock out with the user agent, has no effect when ONLY_USER_FAILURES is set
    USE_USER_AGENT = False

    # use a specific username field to retrieve from login POST data
    USERNAME_FORM_FIELD = "username"

    # use a specific password field to retrieve from login POST data
    PASSWORD_FORM_FIELD = "password"  # noqa

    # use a provided callable to transform the POSTed username into the one used in credentials
    USERNAME_CALLABLE = None

    # determine if given user should be always allowed to attempt authentication
    WHITELIST_CALLABLE = None

    # return custom lockout response if configured
    LOCKOUT_CALLABLE = None

    # reset the number of failed attempts after one successful attempt
    RESET_ON_SUCCESS = False

    DISABLE_ACCESS_LOG = False

    HANDLER = "axes.handlers.database.AxesDatabaseHandler"

    LOGGER = "axes.watch_login"

    LOCKOUT_TEMPLATE = None

    LOCKOUT_URL = None

    COOLOFF_TIME = None

    VERBOSE = True

    # whitelist and blacklist
    NEVER_LOCKOUT_WHITELIST = False

    NEVER_LOCKOUT_GET = False

    ONLY_WHITELIST = False

    IP_WHITELIST = None

    IP_BLACKLIST = None

    # message to show when locked out and have cooloff enabled
    COOLOFF_MESSAGE = _(
        "Account locked: too many login attempts. Please try again later"
    )

    # message to show when locked out and have cooloff disabled
    PERMALOCK_MESSAGE = _(
        "Account locked: too many login attempts. Contact an admin to unlock your account."
    )

    # if your deployment is using reverse proxies, set this value to 'left-most' or 'right-most' per your configuration
    PROXY_ORDER = "left-most"

    # if your deployment is using reverse proxies, set this value to the number of proxies in front of Django
    PROXY_COUNT = None

    # if your deployment is using reverse proxies, set to your trusted proxy IP addresses prefixes if needed
    PROXY_TRUSTED_IPS = None

    # set to the names of request.META attributes that should be checked for the IP address of the client
    # if your deployment is using reverse proxies, ensure that the header attributes are securely set by the proxy
    # ensure that the client can not spoof the headers by setting them and sending them through the proxy
    META_PRECEDENCE_ORDER = getattr(
        settings,
        "AXES_META_PRECEDENCE_ORDER",
        getattr(settings, "IPWARE_META_PRECEDENCE_ORDER", ("REMOTE_ADDR",)),
    )

    # set to `True` if using with Django REST Framework
    REST_FRAMEWORK_ACTIVE = False
