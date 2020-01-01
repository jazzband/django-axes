from axes.handlers.base import AxesHandler


class AxesTestHandler(AxesHandler):  # pylint: disable=unused-argument
    """
    Signal handler implementation that does nothing, ideal for a test suite.
    """

    def is_allowed(self, request, credentials: dict = None) -> bool:
        return True
 
    def reset_attempts(self, *, ip_address: str = None, username: str = None) -> int:
        pass

    def reset_logs(self, *, age_days: int = None) -> int:
        pass
