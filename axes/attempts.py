from collections import OrderedDict
from hashlib import md5
from logging import getLogger

from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone

from axes.conf import settings
from axes.models import AccessAttempt
from axes.utils import (
    get_axes_cache,
    get_client_ip,
    get_client_username,
    get_client_user_agent,
    get_cache_timeout,
    get_cool_off,
)

log = getLogger(settings.AXES_LOGGER)


def get_filter_kwargs(username: str, ip_address: str, user_agent: str) -> OrderedDict:
    """
    Get query parameters for filtering AccessAttempt queryset.

    This method returns an OrderedDict that guarantees iteration order for keys and values,
    and can so be used in e.g. the generation of hash keys or other deterministic functions.
    """

    query = OrderedDict()  # type: OrderedDict

    if settings.AXES_ONLY_USER_FAILURES:
        query['username'] = username
    else:
        if settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            query['username'] = username
            query['ip_address'] = ip_address
        else:
            query['ip_address'] = ip_address

        if settings.AXES_USE_USER_AGENT:
            query['user_agent'] = user_agent

    return query


def query_user_attempts(request: HttpRequest, credentials: dict = None) -> QuerySet:
    """
    Return a queryset of AccessAttempts that match the given request and credentials.
    """

    username = get_client_username(request, credentials)
    ip_address = get_client_ip(request)
    user_agent = get_client_user_agent(request)

    filter_kwargs = get_filter_kwargs(username, ip_address, user_agent)

    return AccessAttempt.objects.filter(**filter_kwargs)


def get_cache_key(request_or_attempt, credentials: dict = None) -> str:
    """
    Build cache key name from request or AccessAttempt object.

    :param request_or_attempt: HttpRequest or AccessAttempt object
    :param credentials: credentials containing user information
    :return cache_key: Hash key that is usable for Django cache backends
    """

    if isinstance(request_or_attempt, AccessAttempt):
        username = request_or_attempt.username
        ip_address = request_or_attempt.ip_address
        user_agent = request_or_attempt.user_agent
    else:
        username = get_client_username(request_or_attempt, credentials)
        ip_address = get_client_ip(request_or_attempt)
        user_agent = get_client_user_agent(request_or_attempt)

    filter_kwargs = get_filter_kwargs(username, ip_address, user_agent)

    cache_key_components = ''.join(filter_kwargs.values())
    cache_key_digest = md5(cache_key_components.encode()).hexdigest()
    cache_key = 'axes-{}'.format(cache_key_digest)

    return cache_key


def get_user_attempts(request: HttpRequest, credentials: dict = None):
    force_reload = False
    attempts = query_user_attempts(request, credentials)
    cache_hash_key = get_cache_key(request, credentials)
    cache_timeout = get_cache_timeout()
    cool_off = get_cool_off()

    if cool_off:
        for attempt in attempts:
            if attempt.attempt_time + cool_off < timezone.now():
                attempt.delete()
                force_reload = True
                failures_cached = get_axes_cache().get(cache_hash_key)
                if failures_cached is not None:
                    get_axes_cache().set(
                        cache_hash_key, failures_cached - 1, cache_timeout
                    )

    # If objects were deleted, we need to update the queryset to reflect this,
    # so force a reload.
    if force_reload:
        attempts = query_user_attempts(request, credentials)

    return attempts


def reset_user_attempts(request: HttpRequest, credentials: dict = None) -> int:
    attempts = query_user_attempts(request, credentials)
    count, _ = attempts.delete()

    return count


def ip_in_whitelist(ip: str) -> bool:
    if not settings.AXES_IP_WHITELIST:
        return False

    return ip in settings.AXES_IP_WHITELIST


def ip_in_blacklist(ip: str) -> bool:
    if not settings.AXES_IP_BLACKLIST:
        return False

    return ip in settings.AXES_IP_BLACKLIST


def is_ip_blacklisted(request: HttpRequest) -> bool:
    """
    Check if the given request refers to a blacklisted IP.
    """

    ip = get_client_ip(request)

    if settings.AXES_NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip):
        return False

    if settings.AXES_ONLY_WHITELIST and not ip_in_whitelist(ip):
        return True

    if ip_in_blacklist(ip):
        return True

    return False


def is_user_lockable(request: HttpRequest, credentials: dict = None) -> bool:
    """
    Check if the given request or credentials refer to a whitelisted user object

    A whitelisted user has the magic ``nolockout`` property set.

    If the property is unknown or False or the user can not be found,
    this implementation fails gracefully and returns True.
    """

    username_field = getattr(get_user_model(), 'USERNAME_FIELD', 'username')
    username_value = get_client_username(request, credentials)
    kwargs = {
        username_field: username_value
    }

    UserModel = get_user_model()

    try:
        user = UserModel.objects.get(**kwargs)
        return not user.nolockout
    except (UserModel.DoesNotExist, AttributeError):
        pass

    return True


def is_already_locked(request: HttpRequest, credentials: dict = None) -> bool:
    """
    Check if the request or given credentials are already locked by Axes.

    This function is called from

    - function decorators defined in ``axes.decorators``,
    - authentication backends defined in ``axes.backends``, and
    - signal handlers defined in ``axes.handlers``.

    This function checks the following facts for a given request:

    1. Is the request HTTP method _whitelisted_? If it is, return ``False``.
    2. Is the request IP address _blacklisted_? If it is, return ``True``.
    3. Does the request or given credentials refer to a whitelisted user? If it does, return ``False``.
    4. Does the request exceed the configured maximum attempt limit? If it does, return ``True``.

    Refer to the function source code for the exact implementation.
    """

    if settings.AXES_NEVER_LOCKOUT_GET and request.method == 'GET':
        return False

    if is_ip_blacklisted(request):
        return True

    if not is_user_lockable(request, credentials):
        return False

    cache_hash_key = get_cache_key(request, credentials)
    failures_cached = get_axes_cache().get(cache_hash_key)
    if failures_cached is not None:
        return (
            failures_cached >= settings.AXES_FAILURE_LIMIT and
            settings.AXES_LOCK_OUT_AT_FAILURE
        )

    for attempt in get_user_attempts(request, credentials):
        if (
            attempt.failures_since_start >= settings.AXES_FAILURE_LIMIT and
            settings.AXES_LOCK_OUT_AT_FAILURE
        ):
            return True

    return False
