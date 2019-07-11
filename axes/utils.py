"""
Axes utility functions that are publicly available.

This module is separate for historical reasons
and offers a backwards compatible import path.
"""

from logging import getLogger

from axes.handlers.proxy import AxesProxyHandler

log = getLogger(__name__)


def reset(ip: str = None, username: str = None) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """

    return AxesProxyHandler.reset_attempts(ip_address=ip, username=username)
