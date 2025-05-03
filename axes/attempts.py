from logging import getLogger
from typing import Optional

from django.http import HttpRequest
from django.utils.timezone import datetime, now

from axes.helpers import get_cool_off

log = getLogger(__name__)


def get_cool_off_threshold(request: Optional[HttpRequest] = None) -> datetime:
    """
    Get threshold for fetching access attempts from the database.
    """

    cool_off = get_cool_off(request)
    if cool_off is None:
        raise TypeError(
            "Cool off threshold can not be calculated with settings.AXES_COOLOFF_TIME set to None"
        )

    attempt_time = request.axes_attempt_time
    if attempt_time is None:
        return now() - cool_off
    return attempt_time - cool_off
