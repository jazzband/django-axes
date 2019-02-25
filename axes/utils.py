"""
Axes utility functions that are publicly available.

This module is separate for historical reasons
and offers a backwards compatible import path.
"""

from logging import getLogger

from axes.models import AccessAttempt

log = getLogger(__name__)


def reset(ip: str = None, username: str = None) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """

    attempts = AccessAttempt.objects.all()

    if ip:
        attempts = attempts.filter(ip_address=ip)
    if username:
        attempts = attempts.filter(username=username)

    count, _ = attempts.delete()
    log.info('AXES: Reset %s access attempts from database.', count)

    return count
