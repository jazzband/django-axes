from axes.handlers.base import AxesBaseHandler, AbstractAxesHandler
from typing import Optional


class AxesDummyHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that does nothing and can be used to disable signal processing.
    """

    def is_allowed(self, request, credentials: Optional[dict] = None) -> bool:
        return True

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        pass

    def user_logged_in(self, sender, request, user, **kwargs):
        pass

    def user_logged_out(self, sender, request, user, **kwargs):
        pass

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        return 0
