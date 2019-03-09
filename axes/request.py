from datetime import datetime

from django.http import HttpRequest


class AxesHttpRequest(HttpRequest):
    """
    Type definition for the HTTP request Axes uses.
    """

    axes_attempt_time: datetime
    axes_ip_address: str
    axes_user_agent: str
    axes_path_info: str
    axes_http_accept: str
