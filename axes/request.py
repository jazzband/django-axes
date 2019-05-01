from datetime import datetime

from django.http import HttpRequest


class AxesHttpRequest(HttpRequest):
    """
    Extended Django ``HttpRequest`` with custom Axes attributes.

    This request is constructed by the ``AxesMiddleware`` class
    where the custom attributes are inserted into the request.

    .. note:: The ``str`` type variables have a maximum length of 255
              characters and they are calculated in the middleware layer.
              If the HTTP request attributes can not be resolved
              they are assigned default value of ``<unknown>``.

    :var axes_attempt_time: Timestamp of the request on the server side.
    :vartype axes_attempt_time: datetime

    :var axes_ip_address: Request IP address as resolved by django-axes and django-ipware configurations.
    :vartype axes_ip_address: str

    :var axes_user_agent: Request agent from ``request.META['HTTP_USER_AGENT']``.
    :vartype axes_user_agent: str

    :var axes_path_info: Request path from ``request.META['PATH_INFO']``.
    :vartype axes_path_info: str

    :var axes_http_accept: Request ``Accept`` header from ``request.META['HTTP_ACCEPT']``.
    :vartype axes_http_accept: str
    """

    axes_attempt_time: datetime
    axes_ip_address: str
    axes_user_agent: str
    axes_path_info: str
    axes_http_accept: str
