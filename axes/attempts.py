from logging import getLogger

from django.db.models import QuerySet
from django.utils.timezone import datetime, now

from axes.conf import settings
from axes.models import AccessAttempt
from axes.helpers import get_client_username, get_client_parameters, get_cool_off

log = getLogger(settings.AXES_LOGGER)


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


def filter_user_attempts(request, credentials: dict = None) -> QuerySet:
    """
    Return a queryset of AccessAttempts that match the given request and credentials.
    """

    username = get_client_username(request, credentials)

    filter_kwargs = get_client_parameters(
        username, request.axes_ip_address, request.axes_user_agent
    )

    return AccessAttempt.objects.filter(**filter_kwargs)


def get_user_attempts(request, credentials: dict = None) -> QuerySet:
    """
    Get valid user attempts that match the given request and credentials.
    """

    attempts = filter_user_attempts(request, credentials)

    if settings.AXES_COOLOFF_TIME is None:
        log.debug(
            "AXES: Getting all access attempts from database because no AXES_COOLOFF_TIME is configured"
        )
        return attempts

    threshold = get_cool_off_threshold(request.axes_attempt_time)
    log.debug("AXES: Getting access attempts that are newer than %s", threshold)
    return attempts.filter(attempt_time__gte=threshold)


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

    attempts = filter_user_attempts(request, credentials)

    count, _ = attempts.delete()
    log.info("AXES: Reset %s access attempts from database.", count)

    return count
