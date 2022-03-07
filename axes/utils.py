"""
Axes utility functions that are publicly available.

This module is separate for historical reasons
and offers a backwards compatible import path.
"""

from logging import getLogger
from typing import Optional

from django.http import HttpRequest

from axes.conf import settings
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_client_ip_address

log = getLogger(__name__)


def reset(ip: str = None, username: str = None, ip_or_username=False) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """

    return AxesProxyHandler.reset_attempts(
        ip_address=ip, username=username, ip_or_username=ip_or_username
    )


def reset_request(request: HttpRequest) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """

    ip: Optional[str] = get_client_ip_address(request)
    username = request.GET.get("username", None)

    ip_or_username = settings.AXES_LOCK_OUT_BY_USER_OR_IP
    if settings.AXES_ONLY_USER_FAILURES:
        ip = None
    elif not (
        settings.AXES_LOCK_OUT_BY_USER_OR_IP
        or settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP
    ):
        username = None

    if not ip and not username:
        return 0
        # We don't want to reset everything, if there is some wrong request parameter

    # if settings.AXES_USE_USER_AGENT:
    # TODO: reset based on user_agent?
    return reset(ip, username, ip_or_username)
