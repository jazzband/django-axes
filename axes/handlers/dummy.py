from django.http import HttpRequest

from axes.handlers.base import AxesHandler


class AxesDummyHandler(AxesHandler):  # pylint: disable=unused-argument
    """
    Signal handler implementation that does nothing and can be used to disable signal processing.
    """

    def is_allowed(self, request: HttpRequest, credentials: dict = None) -> bool:
        return True
