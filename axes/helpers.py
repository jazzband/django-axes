from datetime import timedelta
from hashlib import sha256
from logging import getLogger
from string import Template
from typing import Callable, Optional, Type, Union, List
from urllib.parse import urlencode

from django.core.cache import BaseCache, caches
from django.http import HttpRequest, HttpResponse, JsonResponse, QueryDict
from django.shortcuts import redirect, render
from django.utils.encoding import force_bytes
from django.utils.module_loading import import_string

from axes.conf import settings
from axes.models import AccessBase

log = getLogger(__name__)

try:
    import ipware.ip

    IPWARE_INSTALLED = True
except ImportError:
    IPWARE_INSTALLED = False


def get_cache() -> BaseCache:
    """
    Get the cache instance Axes is configured to use with ``settings.AXES_CACHE`` and use ``'default'`` if not set.
    """

    return caches[getattr(settings, "AXES_CACHE", "default")]


def get_cache_timeout() -> Optional[int]:
    """
    Return the cache timeout interpreted from settings.AXES_COOLOFF_TIME.

    The cache timeout can be either None if not configured or integer of seconds if configured.

    Notice that the settings.AXES_COOLOFF_TIME can be None, timedelta, float, integer, callable, or str path,
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

    Notice that the settings.AXES_COOLOFF_TIME is either None, timedelta, or integer/float of hours,
    and this function offers a unified _timedelta or None_ representation of that configuration
    for use with the Axes internal implementations.

    :exception TypeError: if settings.AXES_COOLOFF_TIME is of wrong type.
    """

    cool_off = settings.AXES_COOLOFF_TIME

    if isinstance(cool_off, int):
        return timedelta(hours=cool_off)
    if isinstance(cool_off, float):
        return timedelta(minutes=cool_off * 60)
    if isinstance(cool_off, str):
        return import_string(cool_off)()
    if callable(cool_off):
        return cool_off()  # pylint: disable=not-callable

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


def get_credentials(username: Optional[str] = None, **kwargs) -> dict:
    """
    Calculate credentials for Axes to use internally from given username and kwargs.

    Axes will set the username value into the key defined with ``settings.AXES_USERNAME_FORM_FIELD``
    and update the credentials dictionary with the kwargs given on top of that.
    """

    credentials = {settings.AXES_USERNAME_FORM_FIELD: username}
    credentials.update(kwargs)
    return credentials


def get_client_username(
    request: HttpRequest, credentials: Optional[dict] = None
) -> str:
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
            return settings.AXES_USERNAME_CALLABLE(  # pylint: disable=not-callable
                request, credentials
            )
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


def get_client_ip_address(
    request: HttpRequest,
    use_ipware: Optional[bool] = None,
) -> Optional[str]:
    """
    Get client IP address as configured by the user.

    The order of preference for address resolution is as follows:

    1. If configured, use ``AXES_CLIENT_IP_CALLABLE``, and supply ``request`` as argument
    2. If available, use django-ipware package (parameters can be configured in the Axes package)
    3. Use ``request.META.get('REMOTE_ADDR', None)`` as a fallback

    :param request: incoming Django ``HttpRequest`` or similar object from authentication backend or other source
    """

    if settings.AXES_CLIENT_IP_CALLABLE:
        log.debug("Using settings.AXES_CLIENT_IP_CALLABLE to get client IP address")

        if callable(settings.AXES_CLIENT_IP_CALLABLE):
            return settings.AXES_CLIENT_IP_CALLABLE(  # pylint: disable=not-callable
                request
            )
        if isinstance(settings.AXES_CLIENT_IP_CALLABLE, str):
            return import_string(settings.AXES_CLIENT_IP_CALLABLE)(request)
        raise TypeError(
            "settings.AXES_CLIENT_IP_CALLABLE needs to be a string, callable, or None."
        )

    # Resolve using django-ipware from a configuration flag that can be set to False to explicitly disable
    # this is added to both enable or disable the branch when ipware is installed in the test environment
    if use_ipware is None:
        use_ipware = IPWARE_INSTALLED
    if use_ipware:
        log.debug("Using django-ipware to get client IP address")

        client_ip_address, _ = ipware.ip.get_client_ip(
            request,
            proxy_order=settings.AXES_IPWARE_PROXY_ORDER,
            proxy_count=settings.AXES_IPWARE_PROXY_COUNT,
            proxy_trusted_ips=settings.AXES_IPWARE_PROXY_TRUSTED_IPS,
            request_header_order=settings.AXES_IPWARE_META_PRECEDENCE_ORDER,
        )
        return client_ip_address

    log.debug(
        "Using request.META.get('REMOTE_ADDR', None) fallback method to get client IP address"
    )
    return request.META.get("REMOTE_ADDR", None)


def get_client_user_agent(request: HttpRequest) -> str:
    return request.META.get("HTTP_USER_AGENT", "<unknown>")[:255]


def get_client_path_info(request: HttpRequest) -> str:
    return request.META.get("PATH_INFO", "<unknown>")[:255]


def get_client_http_accept(request: HttpRequest) -> str:
    return request.META.get("HTTP_ACCEPT", "<unknown>")[:1025]


def get_lockout_parameters(
    request_or_attempt: Union[HttpRequest, AccessBase],
    credentials: Optional[dict] = None,
) -> List[Union[str, List[str]]]:
    if callable(settings.AXES_LOCKOUT_PARAMETERS):
        return settings.AXES_LOCKOUT_PARAMETERS(request_or_attempt, credentials)

    if isinstance(settings.AXES_LOCKOUT_PARAMETERS, str):
        return import_string(settings.AXES_LOCKOUT_PARAMETERS)(
            request_or_attempt, credentials
        )

    if isinstance(settings.AXES_LOCKOUT_PARAMETERS, list):
        return settings.AXES_LOCKOUT_PARAMETERS

    raise TypeError(
        "settings.AXES_LOCKOUT_PARAMETERS needs to be a callable or iterable"
    )


def get_client_parameters(
    username: str,
    ip_address: str,
    user_agent: str,
    request_or_attempt: Union[HttpRequest, AccessBase],
    credentials: Optional[dict] = None,
) -> List[dict]:
    """
    Get query parameters for filtering AccessAttempt queryset.

    This method returns a dict that guarantees iteration order for keys and values,
    and can so be used in e.g. the generation of hash keys or other deterministic functions.

    Returns list of dict, every item of list are separate parameters
    """
    lockout_parameters = get_lockout_parameters(request_or_attempt, credentials)

    parameters_dict = {
        "username": username,
        "ip_address": ip_address,
        "user_agent": user_agent,
    }

    filter_kwargs = []

    for parameter in lockout_parameters:
        try:
            if isinstance(parameter, str):
                filter_kwarg = {parameter: parameters_dict[parameter]}
            else:
                filter_kwarg = {
                    combined_parameter: parameters_dict[combined_parameter]
                    for combined_parameter in parameter
                }
            filter_kwargs.append(filter_kwarg)

        except KeyError as e:
            error_msg = (
                f"{e} lockout parameter is not allowed. "
                f"Allowed parameters: {', '.join(parameters_dict.keys())}"
            )
            log.exception(error_msg)
            raise ValueError(error_msg) from e

    return filter_kwargs


def make_cache_key_list(filter_kwargs_list: List[dict]) -> List[str]:
    cache_keys = []
    for filter_kwargs in filter_kwargs_list:
        cache_key_components = "".join(
            value for value in filter_kwargs.values() if value
        )
        cache_key_digest = sha256(cache_key_components.encode()).hexdigest()
        cache_keys.append(f"axes-{cache_key_digest}")
    return cache_keys


def get_client_cache_keys(
    request_or_attempt: Union[HttpRequest, AccessBase],
    credentials: Optional[dict] = None,
) -> List[str]:
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

    filter_kwargs_list = get_client_parameters(
        username, ip_address, user_agent, request_or_attempt, credentials
    )

    return make_cache_key_list(filter_kwargs_list)


def get_client_str(
    username: str,
    ip_address: str,
    user_agent: str,
    path_info: str,
    request: HttpRequest,
) -> str:
    """
    Get a readable string that can be used in e.g. logging to distinguish client requests.

    Example log format would be
    ``{username: "example", ip_address: "127.0.0.1", path_info: "/example/"}``
    """

    if settings.AXES_CLIENT_STR_CALLABLE:
        log.debug("Using settings.AXES_CLIENT_STR_CALLABLE to get client string.")

        if callable(settings.AXES_CLIENT_STR_CALLABLE):
            return settings.AXES_CLIENT_STR_CALLABLE(  # pylint: disable=not-callable
                username, ip_address, user_agent, path_info, request
            )
        if isinstance(settings.AXES_CLIENT_STR_CALLABLE, str):
            return import_string(settings.AXES_CLIENT_STR_CALLABLE)(
                username, ip_address, user_agent, path_info, request
            )
        raise TypeError(
            "settings.AXES_CLIENT_STR_CALLABLE needs to be a string, callable or None."
        )

    client_dict = {}

    if settings.AXES_VERBOSE:
        # Verbose mode logs every attribute that is available
        client_dict["username"] = username
        client_dict["ip_address"] = ip_address
        client_dict["user_agent"] = user_agent
    else:
        # Other modes initialize the attributes that are used for the actual lockouts
        client_list = get_client_parameters(username, ip_address, user_agent, request)
        client_dict = {}
        for client in client_list:
            client_dict.update(client)
    client_dict = cleanse_parameters(client_dict.copy())
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


def cleanse_parameters(params: dict) -> dict:
    """
    Replace sensitive parameter values in a parameter dict with
    a safe placeholder value.

    Parameters name ``'password'`` will always be cleansed.  Additionally,
    parameters named in ``settings.AXES_SENSITIVE_PARAMETERS`` and
    ``settings.AXES_PASSWORD_FORM_FIELD will be cleansed.

    This is used to prevent passwords and similar values from
    being logged in cleartext.
    """
    sensitive_parameters = ["password"] + settings.AXES_SENSITIVE_PARAMETERS
    if settings.AXES_PASSWORD_FORM_FIELD:
        sensitive_parameters.append(settings.AXES_PASSWORD_FORM_FIELD)

    if sensitive_parameters:
        cleansed = params.copy()
        for param in sensitive_parameters:
            if param in cleansed:
                cleansed[param] = "********************"
        return cleansed
    return params


def get_query_str(query: Type[QueryDict], max_length: int = 1024) -> str:
    """
    Turns a query dictionary into an easy-to-read list of key-value pairs.

    If a field is called either ``'password'`` or ``settings.AXES_PASSWORD_FORM_FIELD`` or if the fieldname is included
    in ``settings.AXES_SENSITIVE_PARAMETERS`` its value will be masked.

    The length of the output is limited to max_length to avoid a DoS attack via excessively large payloads.
    """

    query_dict = cleanse_parameters(query.copy())

    template = Template("$key=$value")
    items = [{"key": k, "value": v} for k, v in query_dict.items()]
    query_str = "\n".join(template.substitute(item) for item in items)

    return query_str[:max_length]


def get_failure_limit(request: HttpRequest, credentials) -> int:
    if callable(settings.AXES_FAILURE_LIMIT):
        return settings.AXES_FAILURE_LIMIT(  # pylint: disable=not-callable
            request, credentials
        )
    if isinstance(settings.AXES_FAILURE_LIMIT, str):
        return import_string(settings.AXES_FAILURE_LIMIT)(request, credentials)
    if isinstance(settings.AXES_FAILURE_LIMIT, int):
        return settings.AXES_FAILURE_LIMIT
    raise TypeError("settings.AXES_FAILURE_LIMIT needs to be a callable or an integer")


def get_lockout_message() -> str:
    if settings.AXES_COOLOFF_TIME:
        return settings.AXES_COOLOFF_MESSAGE
    return settings.AXES_PERMALOCK_MESSAGE


def get_lockout_response(
    request: HttpRequest, credentials: Optional[dict] = None
) -> HttpResponse:
    if settings.AXES_LOCKOUT_CALLABLE:
        if callable(settings.AXES_LOCKOUT_CALLABLE):
            return settings.AXES_LOCKOUT_CALLABLE(  # pylint: disable=not-callable
                request, credentials
            )
        if isinstance(settings.AXES_LOCKOUT_CALLABLE, str):
            return import_string(settings.AXES_LOCKOUT_CALLABLE)(request, credentials)
        raise TypeError(
            "settings.AXES_LOCKOUT_CALLABLE needs to be a string, callable, or None."
        )

    status = settings.AXES_HTTP_RESPONSE_CODE
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
        json_response["Access-Control-Allow-Origin"] = (
            settings.AXES_ALLOWED_CORS_ORIGINS
        )
        json_response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        json_response["Access-Control-Allow-Headers"] = (
            "Origin, Content-Type, Accept, Authorization, x-requested-with"
        )
        return json_response

    if settings.AXES_LOCKOUT_TEMPLATE:
        return render(request, settings.AXES_LOCKOUT_TEMPLATE, context, status=status)

    if settings.AXES_LOCKOUT_URL:
        lockout_url = settings.AXES_LOCKOUT_URL
        query_string = urlencode({"username": context["username"]})
        url = f"{lockout_url}?{query_string}"
        return redirect(url)

    return HttpResponse(get_lockout_message(), status=status)


def is_ip_address_in_whitelist(ip_address: str) -> bool:
    if not settings.AXES_IP_WHITELIST:
        return False

    return (  # pylint: disable=unsupported-membership-test
        ip_address in settings.AXES_IP_WHITELIST
    )


def is_ip_address_in_blacklist(ip_address: str) -> bool:
    if not settings.AXES_IP_BLACKLIST:
        return False

    return (  # pylint: disable=unsupported-membership-test
        ip_address in settings.AXES_IP_BLACKLIST
    )


def is_client_ip_address_whitelisted(request: HttpRequest):
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


def is_client_ip_address_blacklisted(request: HttpRequest) -> bool:
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


def is_client_method_whitelisted(request: HttpRequest) -> bool:
    """
    Check if the given request uses a whitelisted method.
    """

    if settings.AXES_NEVER_LOCKOUT_GET and request.method == "GET":
        return True

    return False


def is_user_attempt_whitelisted(
    request: HttpRequest, credentials: Optional[dict] = None
) -> bool:
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
        return whitelist_callable(request, credentials)  # pylint: disable=not-callable
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


def get_client_session_hash(request: HttpRequest) -> str:
    """
    Get client session and returns the SHA256 hash of session key, forcing session creation if required.

    If no session is available on request returns an empty string.
    """
    try:
        session = request.session
    except AttributeError:
        # when no session is available just return an empty string
        return ""

    # ensure that a session key exists at this point
    # because session middleware usually creates the session key at the end
    # of request cycle
    if session.session_key is None:
        session.create()

    return sha256(force_bytes(session.session_key)).hexdigest()
