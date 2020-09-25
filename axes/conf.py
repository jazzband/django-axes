from django.conf import settings
from django.utils.translation import gettext_lazy as _


DEFAULTS = {
    # disable plugin when set to False
    "AXES_ENABLED": getattr(settings, "AXES_ENABLED", True),
    # see if the user has overridden the failure limit
    "AXES_FAILURE_LIMIT": getattr(settings, "AXES_FAILURE_LIMIT", 3),
    # see if the user has set axes to lock out logins after failure limit
    "AXES_LOCK_OUT_AT_FAILURE": getattr(settings, "AXES_LOCK_OUT_AT_FAILURE", True),
    # lock out with the combination of username and IP address
    "AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP": getattr(settings, "AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP", False),
    # lock out with the username or IP address
    "AXES_LOCK_OUT_BY_USER_OR_IP": getattr(settings, "AXES_LOCK_OUT_BY_USER_OR_IP", False),
    # lock out with username and never the IP or user agent
    "AXES_ONLY_USER_FAILURES": getattr(settings, "AXES_ONLY_USER_FAILURES", False),
    # lock out just for admin site
    "AXES_ONLY_ADMIN_SITE": getattr(settings, "AXES_ONLY_ADMIN_SITE", False),
    # show Axes logs in admin
    "AXES_ENABLE_ADMIN": getattr(settings, "AXES_ENABLE_ADMIN", True),
    # lock out with the user agent, has no effect when ONLY_USER_FAILURES is set
    "AXES_USE_USER_AGENT": getattr(settings, "AXES_USE_USER_AGENT", False),
    # use a specific username field to retrieve from login POST data
    "AXES_USERNAME_FORM_FIELD": getattr(settings, "AXES_USERNAME_FORM_FIELD", "username"),
    # use a specific password field to retrieve from login POST data
    "AXES_PASSWORD_FORM_FIELD": getattr(settings, "AXES_PASSWORD_FORM_FIELD", "password"),  # noqa
    # use a provided callable to transform the POSTed username into the one used in credentials
    "AXES_USERNAME_CALLABLE": getattr(settings, "AXES_USERNAME_CALLABLE", None),
    # determine if given user should be always allowed to attempt authentication
    "AXES_WHITELIST_CALLABLE": getattr(settings, "AXES_WHITELIST_CALLABLE", None),
    # return custom lockout response if configured
    "AXES_LOCKOUT_CALLABLE": getattr(settings, "AXES_LOCKOUT_CALLABLE", None),
    # reset the number of failed attempts after one successful attempt
    "AXES_RESET_ON_SUCCESS": getattr(settings, "AXES_RESET_ON_SUCCESS", False),
    "AXES_DISABLE_ACCESS_LOG": getattr(settings, "AXES_DISABLE_ACCESS_LOG", False),
    "AXES_HANDLER": getattr(settings, "AXES_HANDLER", "axes.handlers.database.AxesDatabaseHandler"),
    "AXES_LOGGER": getattr(settings, "AXES_LOGGER", "axes.watch_login"),
    "AXES_LOCKOUT_TEMPLATE": getattr(settings, "AXES_LOCKOUT_TEMPLATE", None),
    "AXES_LOCKOUT_URL": getattr(settings, "AXES_LOCKOUT_URL", None),
    "AXES_COOLOFF_TIME": getattr(settings, "AXES_COOLOFF_TIME", None),
    "AXES_VERBOSE": getattr(settings, "AXES_VERBOSE", True),
    # whitelist and blacklist
    "AXES_NEVER_LOCKOUT_WHITELIST": getattr(settings, "AXES_NEVER_LOCKOUT_WHITELIST", False),
    "AXES_NEVER_LOCKOUT_GET": getattr(settings, "AXES_NEVER_LOCKOUT_GET", False),
    "AXES_ONLY_WHITELIST": getattr(settings, "AXES_ONLY_WHITELIST", False),
    "AXES_IP_WHITELIST": getattr(settings, "AXES_IP_WHITELIST", None),
    "AXES_IP_BLACKLIST": getattr(settings, "AXES_IP_BLACKLIST", None),
    # message to show when locked out and have cooloff enabled
    "AXES_COOLOFF_MESSAGE": getattr(
        settings,
        "AXES_COOLOFF_MESSAGE",
        _("Account locked: too many login attempts. Please try again later"),
    ),
    # message to show when locked out and have cooloff disabled
    "AXES_PERMALOCK_MESSAGE": getattr(
        settings,
        "AXES_PERMALOCK_MESSAGE",
        _("Account locked: too many login attempts. Contact an admin to unlock your account."),
    ),
    # if your deployment is using reverse proxies, set this value to 'left-most' or 'right-most' per your configuration
    "AXES_PROXY_ORDER": getattr(settings, "AXES_PROXY_ORDER", "left-most"),
    # if your deployment is using reverse proxies, set this value to the number of proxies in front of Django
    "AXES_PROXY_COUNT": getattr(settings, "AXES_PROXY_COUNT", None),
    # if your deployment is using reverse proxies, set to your trusted proxy IP addresses prefixes if needed
    "AXES_PROXY_TRUSTED_IPS": getattr(settings, "AXES_PROXY_TRUSTED_IPS", None),
    # set to the names of request.META attributes that should be checked for the IP address of the client
    # if your deployment is using reverse proxies, ensure that the header attributes are securely set by the proxy
    # ensure that the client can not spoof the headers by setting them and sending them through the proxy
    "AXES_META_PRECEDENCE_ORDER": getattr(
        settings,
        "AXES_META_PRECEDENCE_ORDER",
        getattr(settings, "IPWARE_META_PRECEDENCE_ORDER", ("REMOTE_ADDR",)),
    ),
    # set to `True` if using with Django REST Framework
    "AXES_REST_FRAMEWORK_ACTIVE": getattr(settings, "AXES_REST_FRAMEWORK_ACTIVE", False),
}


class AxesSettings:
    """
    A settings object, that allows Axes settings to be accessed as properties.
    """

    def __init__(self, defaults=None):
        self.defaults = defaults or {}

    def __getattr__(self, attr):
        if attr not in self.defaults.keys():
            raise AttributeError("Invalid Axes setting: %r" % (attr))
        val = self.defaults[attr]
        # Cache the result
        setattr(self, attr, val)
        return val


axes_settings = AxesSettings(DEFAULTS)
