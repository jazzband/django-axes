from axes.handlers.base import AxesHandler
from typing import Optional


class AxesTestHandler(AxesHandler):
    """
    Signal handler implementation that does nothing, ideal for a test suite.
    """

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        return 0

    def reset_logs(self, *, age_days: Optional[int] = None) -> int:
        return 0

    def is_allowed(self, request, credentials: Optional[dict] = None) -> bool:
        return True

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        return 0
