from datetime import datetime  # noqa

from django.http import HttpRequest


class AxesHttpRequest(HttpRequest):
    """
    Type definition for the HTTP request Axes uses.
    """

    def __init__(self):
        super().__init__()

        # TODO: Move attribute definitions to class level in Python 3.6+
        self.axes_attempt_time = None  # type: datetime
        self.axes_ip_address = None    # type: str
        self.axes_user_agent = None    # type: str
        self.axes_path_info = None     # type: str
        self.axes_http_accept = None   # type: str
