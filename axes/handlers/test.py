from axes.handlers.base import AxesHandler


class AxesTestHandler(AxesHandler):  # pylint: disable=unused-argument
    """
    Signal handler implementation that does nothing, ideal for a test suite.
    """

    def reset_attempts(
        self,
        *,
        ip_address: str = None,
        username: str = None,
        ip_or_username: bool = False,
    ) -> int:
        return 0

    def reset_logs(self, *, age_days: int = None) -> int:
        return 0

    def is_allowed(self, request, credentials: dict = None) -> bool:
        return True

    def get_failures(self, request, credentials: dict = None) -> int:
        return 0
