from hashlib import md5
from logging import getLogger
from typing import Union

from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.timezone import now

from axes.conf import settings
from axes.models import AccessAttempt
from axes.utils import (
    get_axes_cache,
    get_client_ip_address,
    get_client_username,
    get_client_user_agent,
    get_cache_timeout,
    get_cool_off,
    get_client_parameters,
)

log = getLogger(settings.AXES_LOGGER)


def get_cache_key(request_or_attempt: Union[HttpRequest, AccessAttempt], credentials: dict = None) -> str:
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
        ip_address = get_client_ip_address(request_or_attempt)
        user_agent = get_client_user_agent(request_or_attempt)

    filter_kwargs = get_client_parameters(username, ip_address, user_agent)

    cache_key_components = ''.join(filter_kwargs.values())
    cache_key_digest = md5(cache_key_components.encode()).hexdigest()
    cache_key = 'axes-{}'.format(cache_key_digest)

    return cache_key


def filter_user_attempts(request: HttpRequest, credentials: dict = None) -> QuerySet:
    """
    Return a queryset of AccessAttempts that match the given request and credentials.
    """

    username = get_client_username(request, credentials)
    ip_address = get_client_ip_address(request)
    user_agent = get_client_user_agent(request)

    filter_kwargs = get_client_parameters(username, ip_address, user_agent)

    return AccessAttempt.objects.filter(**filter_kwargs)


def get_user_attempts(request: HttpRequest, credentials: dict = None) -> QuerySet:
    """
    Get valid user attempts and delete expired attempts which have cool offs in the past.
    """

    attempts = filter_user_attempts(request, credentials)

    # If settings.AXES_COOLOFF_TIME is not configured return the attempts
    cool_off = get_cool_off()
    if cool_off is None:
        return attempts

    # Else AccessAttempts that have expired need to be cleaned up from the database
    num_deleted, _ = attempts.filter(attempt_time__lte=now() - cool_off).delete()
    if not num_deleted:
        return attempts

    # If there deletions the cache needs to be updated
    cache_key = get_cache_key(request, credentials)
    num_failures_cached = get_axes_cache().get(cache_key)
    if num_failures_cached is not None:
        get_axes_cache().set(
            cache_key,
            num_failures_cached - num_deleted,
            get_cache_timeout(),
        )

    # AccessAttempts need to be refreshed from the database because of the delete before returning them
    return attempts.all()


def reset_user_attempts(request: HttpRequest, credentials: dict = None) -> int:
    """
    Reset all user attempts that match the given request and credentials.
    """

    attempts = filter_user_attempts(request, credentials)
    count, _ = attempts.delete()

    return count
