from datetime import timedelta
from hashlib import md5
from logging import getLogger
from string import Template
from typing import Callable, Optional, Type, Union
from urllib.parse import urlencode

import ipware.ip
from django.core.cache import caches, BaseCache
from django.http import HttpRequest, HttpResponse, JsonResponse, QueryDict
from django.shortcuts import render, redirect
from django.utils.module_loading import import_string

from axes.conf import settings
from axes.models import AccessBase

log = getLogger(__name__)


def get_cache() -> BaseCache:
    """
    Get the cache instance Axes is configured to use with ``settings.AXES_CACHE`` and use ``'default'`` if not set.
    """

    return caches[getattr(settings, "AXES_CACHE", "default")]


def get_cache_timeout() -> Optional[int]:
    """
    Return the cache timeout interpreted from settings.AXES_COOLOFF_TIME.

    The cache timeout can be either None if not configured or integer of seconds if configured.

    Notice that the settings.AXES_COOLOFF_TIME can be None, timedelta, integer, callable, or str path,
    and this function offers a unified _integer or None_ representation of that configuration
    for use with the Django cache backends.
    """

    cool_off = get_cool_off()
    if cool_off is None:
        return None
    return int(cool_off.total_seconds())


def get_cool_off() -> Optional[timedelta]:
    """
    Return the login cool off time interpreted from settings.AXES_COOLOFF_TIME.

    The return value is either None or timedelta.

    Notice that the settings.AXES_COOLOFF_TIME is either None, timedelta, or integer of hours,
    and this function offers a unified _timedelta or None_ representation of that configuration
    for use with the Axes internal implementations.

    :exception TypeError: if settings.AXES_COOLOFF_TIME is of wrong type.
    """

    cool_off = settings.AXES_COOLOFF_TIME

    if isinstance(cool_off, int):
        return timedelta(hours=cool_off)
    if isinstance(cool_off, str):
        return import_string(cool_off)()
    if callable(cool_off):
        return cool_off()

    return cool_off


def get_cool_off_iso8601(delta: timedelta) -> str:
    """
    Return datetime.timedelta translated to ISO 8601 formatted duration for use in e.g. cool offs.
    """

    seconds = delta.total_seconds()
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    days_str = f"{days:.0f}D" if days else ""

    time_str = "".join(
        f"{value:.0f}{designator}"
        for value, designator in [[hours, "H"], [minutes, "M"], [seconds, "S"]]
        if value
    )

    if time_str:
        return f"P{days_str}T{time_str}"
    return f"P{days_str}"


def get_credentials(username: str = None, **kwargs) -> dict:
    """
    Calculate credentials for Axes to use internally from given username and kwargs.

    Axes will set the username value into the key defined with ``settings.AXES_USERNAME_FORM_FIELD``
    and update the credentials dictionary with the kwargs given on top of that.
    """

    credentials = {settings.AXES_USERNAME_FORM_FIELD: username}
    credentials.update(kwargs)
    return credentials


def get_client_username(request, credentials: dict = None) -> str:
    """
    Resolve client username from the given request or credentials if supplied.

    The order of preference for fetching the username is as follows:

    1. If configured, use ``AXES_USERNAME_CALLABLE``, and supply ``request, credentials`` as arguments
    2. If given, use ``credentials`` and fetch username from ``AXES_USERNAME_FORM_FIELD`` (defaults to ``username``)
    3. Use request.POST and fetch username from ``AXES_USERNAME_FORM_FIELD`` (defaults to ``username``)

    :param request: incoming Django ``HttpRequest`` or similar object from authentication backend or other source
    :param credentials: incoming credentials ``dict`` or similar object from authentication backend or other source
    """

    if settings.AXES_USERNAME_CALLABLE:
        log.debug("Using settings.AXES_USERNAME_CALLABLE to get username")

        if callable(settings.AXES_USERNAME_CALLABLE):
            return settings.AXES_USERNAME_CALLABLE(request, credentials)
        if isinstance(settings.AXES_USERNAME_CALLABLE, str):
            return import_string(settings.AXES_USERNAME_CALLABLE)(request, credentials)
        raise TypeError(
            "settings.AXES_USERNAME_CALLABLE needs to be a string, callable, or None."
        )

    if credentials:
        log.debug(
            "Using parameter credentials to get username with key settings.AXES_USERNAME_FORM_FIELD"
        )
        return credentials.get(settings.AXES_USERNAME_FORM_FIELD, None)

    log.debug(
        "Using parameter request.POST to get username with key settings.AXES_USERNAME_FORM_FIELD"
    )

    request_data = getattr(request, "data", request.POST)
    return request_data.get(settings.AXES_USERNAME_FORM_FIELD, None)


def get_client_ip_address(request) -> str:
    """
    Get client IP address as configured by the user.

    The django-ipware package is used for address resolution
    and parameters can be configured in the Axes package.
    """

    client_ip_address, _ = ipware.ip.get_client_ip(
        request,
        proxy_order=settings.AXES_PROXY_ORDER,
        proxy_count=settings.AXES_PROXY_COUNT,
        proxy_trusted_ips=settings.AXES_PROXY_TRUSTED_IPS,
        request_header_order=settings.AXES_META_PRECEDENCE_ORDER,
    )

    return client_ip_address


def get_client_user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "<unknown>")[:255]


def get_client_path_info(request) -> str:
    return request.META.get("PATH_INFO", "<unknown>")[:255]


def get_client_http_accept(request) -> str:
    return request.META.get("HTTP_ACCEPT", "<unknown>")[:1025]


def get_client_parameters(username: str, ip_address: str, user_agent: str) -> list:
    """
    Get query parameters for filtering AccessAttempt queryset.

    This method returns a dict that guarantees iteration order for keys and values,
    and can so be used in e.g. the generation of hash keys or other deterministic functions.

    Returns list of dict, every item of list are separate parameters
    """

    if settings.AXES_ONLY_USER_FAILURES:
        # 1. Only individual usernames can be tracked with parametrization
        filter_query = [{"username": username}]
    else:
        if settings.AXES_LOCK_OUT_BY_USER_OR_IP:
            # One of `username` or `IP address` is used
            filter_query = [{"username": username}, {"ip_address": ip_address}]
        elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            # 2. A combination of username and IP address can be used as well
            filter_query = [{"username": username, "ip_address": ip_address}]
        else:
            # 3. Default case is to track the IP address only, which is the most secure option
            filter_query = [{"ip_address": ip_address}]

        if settings.AXES_USE_USER_AGENT:
            # 4. The HTTP User-Agent can be used to track e.g. one browser
            filter_query.append({"user_agent": user_agent})

    return filter_query


def make_cache_key_list(filter_kwargs_list):
    cache_keys = []
    for filter_kwargs in filter_kwargs_list:
        cache_key_components = "".join(
            value for value in filter_kwargs.values() if value
        )
        cache_key_digest = md5(cache_key_components.encode()).hexdigest()
        cache_keys.append(f"axes-{cache_key_digest}")
    return cache_keys


def get_client_cache_key(
    request_or_attempt: Union[HttpRequest, AccessBase], credentials: dict = None
) -> str:
    """
    Build cache key name from request or AccessAttempt object.

    :param request_or_attempt: HttpRequest or AccessAttempt object
    :param credentials: credentials containing user information
    :return cache_key: Hash key that is usable for Django cache backends
    """

    if isinstance(request_or_attempt, AccessBase):
        username = request_or_attempt.username
        ip_address = request_or_attempt.ip_address
        user_agent = request_or_attempt.user_agent
    else:
        username = get_client_username(request_or_attempt, credentials)
        ip_address = get_client_ip_address(request_or_attempt)
        user_agent = get_client_user_agent(request_or_attempt)

    filter_kwargs_list = get_client_parameters(username, ip_address, user_agent)

    return make_cache_key_list(filter_kwargs_list)


def get_client_str(
    username: str, ip_address: str, user_agent: str, path_info: str
) -> str:
    """
    Get a readable string that can be used in e.g. logging to distinguish client requests.

    Example log format would be
    ``{username: "example", ip_address: "127.0.0.1", path_info: "/example/"}``
    """

    client_dict = dict()

    if settings.AXES_VERBOSE:
        # Verbose mode logs every attribute that is available
        client_dict["username"] = username
        client_dict["ip_address"] = ip_address
        client_dict["user_agent"] = user_agent
    else:
        # Other modes initialize the attributes that are used for the actual lockouts
        client_list = get_client_parameters(username, ip_address, user_agent)
        client_dict = {}
        for client in client_list:
            client_dict.update(client)

    # Path info is always included as last component in the client string for traceability purposes
    if path_info and isinstance(path_info, (tuple, list)):
        path_info = path_info[0]
    client_dict["path_info"] = path_info

    # Template the internal dictionary representation into a readable and concatenated {key: "value"} format
    template = Template('$key: "$value"')
    items = [{"key": k, "value": v} for k, v in client_dict.items()]
    client_str = ", ".join(template.substitute(item) for item in items)
    client_str = "{" + client_str + "}"
    return client_str


def get_query_str(query: Type[QueryDict], max_length: int = 1024) -> str:
    """
    Turns a query dictionary into an easy-to-read list of key-value pairs.

    If a field is called either ``'password'`` or ``settings.AXES_PASSWORD_FORM_FIELD`` it will be excluded.

    The length of the output is limited to max_length to avoid a DoS attack via excessively large payloads.
    """

    query_dict = query.copy()
    query_dict.pop("password", None)
    query_dict.pop(settings.AXES_PASSWORD_FORM_FIELD, None)

    template = Template("$key=$value")
    items = [{"key": k, "value": v} for k, v in query_dict.items()]
    query_str = "\n".join(template.substitute(item) for item in items)

    return query_str[:max_length]


def get_failure_limit(request, credentials) -> int:
    if callable(settings.AXES_FAILURE_LIMIT):
        return settings.AXES_FAILURE_LIMIT(request, credentials)
    if isinstance(settings.AXES_FAILURE_LIMIT, str):
        return import_string(settings.AXES_FAILURE_LIMIT)(request, credentials)
    if isinstance(settings.AXES_FAILURE_LIMIT, int):
        return settings.AXES_FAILURE_LIMIT
    raise TypeError("settings.AXES_FAILURE_LIMIT needs to be a callable or an integer")


def get_lockout_message() -> str:
    if settings.AXES_COOLOFF_TIME:
        return settings.AXES_COOLOFF_MESSAGE
    return settings.AXES_PERMALOCK_MESSAGE


def get_lockout_response(request, credentials: dict = None) -> HttpResponse:
    if settings.AXES_LOCKOUT_CALLABLE:
        if callable(settings.AXES_LOCKOUT_CALLABLE):
            return settings.AXES_LOCKOUT_CALLABLE(request, credentials)
        if isinstance(settings.AXES_LOCKOUT_CALLABLE, str):
            return import_string(settings.AXES_LOCKOUT_CALLABLE)(request, credentials)
        raise TypeError(
            "settings.AXES_LOCKOUT_CALLABLE needs to be a string, callable, or None."
        )

    status = 403
    context = {
        "failure_limit": get_failure_limit(request, credentials),
        "username": get_client_username(request, credentials) or "",
    }

    cool_off = get_cool_off()
    if cool_off:
        context.update(
            {
                "cooloff_time": get_cool_off_iso8601(
                    cool_off
                ),  # differing old name is kept for backwards compatibility
                "cooloff_timedelta": cool_off,
            }
        )

    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
        json_response = JsonResponse(context, status=status)
        json_response[
            "Access-Control-Allow-Origin"
        ] = settings.AXES_ALLOWED_CORS_ORIGINS
        json_response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        json_response[
            "Access-Control-Allow-Headers"
        ] = "Origin, Content-Type, Accept, Authorization, x-requested-with"
        return json_response

    if settings.AXES_LOCKOUT_TEMPLATE:
        return render(request, settings.AXES_LOCKOUT_TEMPLATE, context, status=status)

    if settings.AXES_LOCKOUT_URL:
        lockout_url = settings.AXES_LOCKOUT_URL
        query_string = urlencode({"username": context["username"]})
        url = "{}?{}".format(lockout_url, query_string)
        return redirect(url)

    return HttpResponse(get_lockout_message(), status=status)


def is_ip_address_in_whitelist(ip_address: str) -> bool:
    if not settings.AXES_IP_WHITELIST:
        return False

    return ip_address in settings.AXES_IP_WHITELIST


def is_ip_address_in_blacklist(ip_address: str) -> bool:
    if not settings.AXES_IP_BLACKLIST:
        return False

    return ip_address in settings.AXES_IP_BLACKLIST


def is_client_ip_address_whitelisted(request):
    """
    Check if the given request refers to a whitelisted IP.
    """

    if settings.AXES_NEVER_LOCKOUT_WHITELIST and is_ip_address_in_whitelist(
        request.axes_ip_address
    ):
        return True

    if settings.AXES_ONLY_WHITELIST and is_ip_address_in_whitelist(
        request.axes_ip_address
    ):
        return True

    return False


def is_client_ip_address_blacklisted(request) -> bool:
    """
    Check if the given request refers to a blacklisted IP.
    """

    if is_ip_address_in_blacklist(request.axes_ip_address):
        return True

    if settings.AXES_ONLY_WHITELIST and not is_ip_address_in_whitelist(
        request.axes_ip_address
    ):
        return True

    return False


def is_client_method_whitelisted(request) -> bool:
    """
    Check if the given request uses a whitelisted method.
    """

    if settings.AXES_NEVER_LOCKOUT_GET and request.method == "GET":
        return True

    return False


def is_user_attempt_whitelisted(request, credentials: dict = None) -> bool:
    """
    Check if the given request or credentials refer to a whitelisted username.

    This method invokes the ``settings.AXES_WHITELIST`` callable
    with ``request`` and ``credentials`` arguments.

    This function could use the following implementation for checking
    the lockout flags from a specific property in the user object:

    .. code-block: python

       username_value = get_client_username(request, credentials)
       username_field = getattr(
           get_user_model(),
           "USERNAME_FIELD",
           "username"
       )
       kwargs = {username_field: username_value}

       user_model = get_user_model()
       user = user_model.objects.get(**kwargs)
       return user.nolockout
    """

    whitelist_callable = settings.AXES_WHITELIST_CALLABLE
    if whitelist_callable is None:
        return False
    if callable(whitelist_callable):
        return whitelist_callable(request, credentials)
    if isinstance(whitelist_callable, str):
        return import_string(whitelist_callable)(request, credentials)

    raise TypeError(
        "settings.AXES_WHITELIST_CALLABLE needs to be a string, callable, or None."
    )


def toggleable(func) -> Callable:
    """
    Decorator that toggles function execution based on settings.

    If the ``settings.AXES_ENABLED`` flag is set to ``False``
    the decorated function never runs and a None is returned.

    This decorator is only suitable for functions that do not
    require return values to be passed back to callers.
    """

    def inner(*args, **kwargs):  # pylint: disable=inconsistent-return-statements
        if settings.AXES_ENABLED:
            return func(*args, **kwargs)

    return inner
