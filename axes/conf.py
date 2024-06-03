from django.conf import settings
from django.utils.translation import gettext_lazy as _

# disable plugin when set to False
settings.AXES_ENABLED = getattr(settings, "AXES_ENABLED", True)

# see if the user has overridden the failure limit
settings.AXES_FAILURE_LIMIT = getattr(settings, "AXES_FAILURE_LIMIT", 3)

# see if the user has set axes to lock out logins after failure limit
settings.AXES_LOCK_OUT_AT_FAILURE = getattr(settings, "AXES_LOCK_OUT_AT_FAILURE", True)

# lockout parameters
# default value will be ["ip_address"] after removing AXES_LOCK_OUT params support
settings.AXES_LOCKOUT_PARAMETERS = getattr(settings, "AXES_LOCKOUT_PARAMETERS", None)

# TODO: remove it in future versions
if settings.AXES_LOCKOUT_PARAMETERS is None:
    if getattr(settings, "AXES_ONLY_USER_FAILURES", False):
        settings.AXES_LOCKOUT_PARAMETERS = ["username"]
    else:
        if getattr(settings, "AXES_LOCK_OUT_BY_USER_OR_IP", False):
            settings.AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
        elif getattr(settings, "AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP", False):
            settings.AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
        else:
            settings.AXES_LOCKOUT_PARAMETERS = ["ip_address"]

    if getattr(settings, "AXES_USE_USER_AGENT", False):
        if isinstance(settings.AXES_LOCKOUT_PARAMETERS[0], str):
            settings.AXES_LOCKOUT_PARAMETERS[0] = [
                settings.AXES_LOCKOUT_PARAMETERS[0],
                "user_agent",
            ]
        else:
            settings.AXES_LOCKOUT_PARAMETERS[0].append("user_agent")

# lock out just for admin site
settings.AXES_ONLY_ADMIN_SITE = getattr(settings, "AXES_ONLY_ADMIN_SITE", False)

# show Axes logs in admin
settings.AXES_ENABLE_ADMIN = getattr(settings, "AXES_ENABLE_ADMIN", True)

# use a specific username field to retrieve from login POST data
settings.AXES_USERNAME_FORM_FIELD = getattr(
    settings, "AXES_USERNAME_FORM_FIELD", "username"
)

# use a specific password field to retrieve from login POST data
settings.AXES_PASSWORD_FORM_FIELD = getattr(
    settings, "AXES_PASSWORD_FORM_FIELD", "password"
)  # noqa

# use a provided callable to transform the POSTed username into the one used in credentials
settings.AXES_USERNAME_CALLABLE = getattr(settings, "AXES_USERNAME_CALLABLE", None)

# determine if given user should be always allowed to attempt authentication
settings.AXES_WHITELIST_CALLABLE = getattr(settings, "AXES_WHITELIST_CALLABLE", None)

# return custom lockout response if configured
settings.AXES_LOCKOUT_CALLABLE = getattr(settings, "AXES_LOCKOUT_CALLABLE", None)

# use a provided callable to get client ip address
settings.AXES_CLIENT_IP_CALLABLE = getattr(settings, "AXES_CLIENT_IP_CALLABLE", None)

# reset the number of failed attempts after one successful attempt
settings.AXES_RESET_ON_SUCCESS = getattr(settings, "AXES_RESET_ON_SUCCESS", False)

settings.AXES_DISABLE_ACCESS_LOG = getattr(settings, "AXES_DISABLE_ACCESS_LOG", False)

settings.AXES_ENABLE_ACCESS_FAILURE_LOG = getattr(
    settings, "AXES_ENABLE_ACCESS_FAILURE_LOG", False
)

settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT = getattr(
    settings, "AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT", 1000
)

settings.AXES_HANDLER = getattr(
    settings, "AXES_HANDLER", "axes.handlers.database.AxesDatabaseHandler"
)

settings.AXES_LOCKOUT_TEMPLATE = getattr(settings, "AXES_LOCKOUT_TEMPLATE", None)

settings.AXES_LOCKOUT_URL = getattr(settings, "AXES_LOCKOUT_URL", None)

settings.AXES_COOLOFF_TIME = getattr(settings, "AXES_COOLOFF_TIME", None)

settings.AXES_VERBOSE = getattr(settings, "AXES_VERBOSE", settings.AXES_ENABLED)

# whitelist and blacklist
settings.AXES_NEVER_LOCKOUT_WHITELIST = getattr(
    settings, "AXES_NEVER_LOCKOUT_WHITELIST", False
)

settings.AXES_NEVER_LOCKOUT_GET = getattr(settings, "AXES_NEVER_LOCKOUT_GET", False)

settings.AXES_ONLY_WHITELIST = getattr(settings, "AXES_ONLY_WHITELIST", False)

settings.AXES_IP_WHITELIST = getattr(settings, "AXES_IP_WHITELIST", None)

settings.AXES_IP_BLACKLIST = getattr(settings, "AXES_IP_BLACKLIST", None)

# message to show when locked out and have cooloff enabled
settings.AXES_COOLOFF_MESSAGE = getattr(
    settings,
    "AXES_COOLOFF_MESSAGE",
    _("Account locked: too many login attempts. Please try again later."),
)

# message to show when locked out and have cooloff disabled
settings.AXES_PERMALOCK_MESSAGE = getattr(
    settings,
    "AXES_PERMALOCK_MESSAGE",
    _(
        "Account locked: too many login attempts. Contact an admin to unlock your account."
    ),
)

# set CORS allowed origins when calling authentication over ajax
settings.AXES_ALLOWED_CORS_ORIGINS = getattr(settings, "AXES_ALLOWED_CORS_ORIGINS", "*")

# set the list of sensitive parameters to cleanse from get/post data before logging
settings.AXES_SENSITIVE_PARAMETERS = getattr(
    settings,
    "AXES_SENSITIVE_PARAMETERS",
    ["username", "ip_address"],
)

# set the callable for the readable string that can be used in
# e.g. logging to distinguish client requests
settings.AXES_CLIENT_STR_CALLABLE = getattr(settings, "AXES_CLIENT_STR_CALLABLE", None)

# set the HTTP response code given by too many requests
settings.AXES_HTTP_RESPONSE_CODE = getattr(settings, "AXES_HTTP_RESPONSE_CODE", 429)

# If True, a failed login attempt during lockout will reset the cool off period
settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT = getattr(
    settings, "AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT", True
)


###
# django-ipware settings for client IP address calculation and proxy detection
# there are old AXES_PROXY_ and AXES_META_ legacy keys present for backwards compatibility
# see https://github.com/un33k/django-ipware for further details
###

# if your deployment is using reverse proxies, set this value to 'left-most' or 'right-most' per your configuration
settings.AXES_IPWARE_PROXY_ORDER = getattr(
    settings,
    "AXES_IPWARE_PROXY_ORDER",
    getattr(settings, "AXES_PROXY_ORDER", "left-most"),
)

# if your deployment is using reverse proxies, set this value to the number of proxies in front of Django
settings.AXES_IPWARE_PROXY_COUNT = getattr(
    settings,
    "AXES_IPWARE_PROXY_COUNT",
    getattr(settings, "AXES_PROXY_COUNT", None),
)

# if your deployment is using reverse proxies, set to your trusted proxy IP addresses prefixes if needed
settings.AXES_IPWARE_PROXY_TRUSTED_IPS = getattr(
    settings,
    "AXES_IPWARE_PROXY_TRUSTED_IPS",
    getattr(settings, "AXES_PROXY_TRUSTED_IPS", None),
)

# set to the names of request.META attributes that should be checked for the IP address of the client
# if your deployment is using reverse proxies, ensure that the header attributes are securely set by the proxy
# ensure that the client can not spoof the headers by setting them and sending them through the proxy
settings.AXES_IPWARE_META_PRECEDENCE_ORDER = getattr(
    settings,
    "AXES_IPWARE_META_PRECEDENCE_ORDER",
    getattr(
        settings,
        "AXES_META_PRECEDENCE_ORDER",
        getattr(settings, "IPWARE_META_PRECEDENCE_ORDER", ("REMOTE_ADDR",)),
    ),
)
