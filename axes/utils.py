"""
Axes utility functions that are publicly available.

This module is separate for historical reasons
and offers a backwards compatible import path.
"""

from logging import getLogger

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


def reset_request(request) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """

    ip = None
    ip = get_client_ip_address(request)
    username = request.GET.get("username", None)

    ip_or_username = False
    if settings.AXES_ONLY_USER_FAILURES:
        ip = None
    else:
        if settings.AXES_LOCK_OUT_BY_USER_OR_IP:
            ip_or_username = True
        elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            ip_or_username = False
        else:
            username = None

    # if settings.AXES_USE_USER_AGENT:
    # TODO: reset based on user_agent?
    return reset(ip, username, ip_or_username)
