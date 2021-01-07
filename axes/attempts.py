from logging import getLogger
from typing import List

from django.db.models import QuerySet
from django.utils.timezone import datetime, now

from axes.conf import settings
from axes.helpers import get_client_username, get_client_parameters, get_cool_off
from axes.models import AccessAttempt

log = getLogger(__name__)


def get_cool_off_threshold(attempt_time: datetime = None) -> datetime:
    """
    Get threshold for fetching access attempts from the database.
    """

    cool_off = get_cool_off()
    if cool_off is None:
        raise TypeError(
            "Cool off threshold can not be calculated with settings.AXES_COOLOFF_TIME set to None"
        )

    if attempt_time is None:
        return now() - cool_off
    return attempt_time - cool_off


def filter_user_attempts(request, credentials: dict = None) -> List[QuerySet]:
    """
    Return a list querysets of AccessAttempts that match the given request and credentials.
    """

    username = get_client_username(request, credentials)

    filter_kwargs_list = get_client_parameters(
        username, request.axes_ip_address, request.axes_user_agent
    )
    attempts_list = [
        AccessAttempt.objects.filter(**filter_kwargs)
        for filter_kwargs in filter_kwargs_list
    ]
    return attempts_list


def get_user_attempts(request, credentials: dict = None) -> List[QuerySet]:
    """
    Get list of querysets with valid user attempts that match the given request and credentials.
    """

    attempts_list = filter_user_attempts(request, credentials)

    if settings.AXES_COOLOFF_TIME is None:
        log.debug(
            "AXES: Getting all access attempts from database because no AXES_COOLOFF_TIME is configured"
        )
        return attempts_list

    threshold = get_cool_off_threshold(request.axes_attempt_time)
    log.debug("AXES: Getting access attempts that are newer than %s", threshold)
    return [attempts.filter(attempt_time__gte=threshold) for attempts in attempts_list]


def clean_expired_user_attempts(attempt_time: datetime = None) -> int:
    """
    Clean expired user attempts from the database.
    """

    if settings.AXES_COOLOFF_TIME is None:
        log.debug(
            "AXES: Skipping clean for expired access attempts because no AXES_COOLOFF_TIME is configured"
        )
        return 0

    threshold = get_cool_off_threshold(attempt_time)
    count, _ = AccessAttempt.objects.filter(attempt_time__lt=threshold).delete()
    log.info(
        "AXES: Cleaned up %s expired access attempts from database that were older than %s",
        count,
        threshold,
    )
    return count


def reset_user_attempts(request, credentials: dict = None) -> int:
    """
    Reset all user attempts that match the given request and credentials.
    """

    attempts_list = filter_user_attempts(request, credentials)

    count = 0
    for attempts in attempts_list:
        _count, _ = attempts.delete()
        count += _count
    log.info("AXES: Reset %s access attempts from database.", count)

    return count
