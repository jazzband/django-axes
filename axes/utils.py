from __future__ import unicode_literals

try:
    import win_inet_pton  # pylint: disable=unused-import
except ImportError:
    pass

from socket import error, inet_pton, AF_INET6

from django.core.cache import caches
from django.utils import six

import ipware.ip2

from axes.conf import settings
from axes.models import AccessAttempt


def get_axes_cache():
    return caches[getattr(settings, 'AXES_CACHE', 'default')]


def query2str(items, max_length=1024):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.

    The length of the output is limited to max_length to avoid a DoS attack
    via excessively large payloads.
    """
    return '\n'.join([
        '%s=%s' % (k, v) for k, v in six.iteritems(items)
        if k != settings.AXES_PASSWORD_FORM_FIELD
    ][:int(max_length / 2)])[:max_length]


def get_client_str(username, ip_address, user_agent=None, path_info=None):
    if settings.AXES_VERBOSE:
        if isinstance(path_info, tuple):
            path_info = path_info[0]
        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        return details.format(username, ip_address, user_agent, path_info)

    if settings.AXES_ONLY_USER_FAILURES:
        client = username
    elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        client = '{0} from {1}'.format(username, ip_address)
    else:
        client = ip_address

    if settings.AXES_USE_USER_AGENT:
        client += '(user-agent={0})'.format(user_agent)

    return client


def get_client_ip(request):
    client_ip_attribute = 'axes_client_ip'

    if not hasattr(request, client_ip_attribute):
        client_ip, _ = ipware.ip2.get_client_ip(
            request,
            proxy_order=settings.AXES_PROXY_ORDER,
            proxy_count=settings.AXES_PROXY_COUNT,
            proxy_trusted_ips=settings.AXES_PROXY_TRUSTED_IPS,
            request_header_order=settings.AXES_META_PRECEDENCE_ORDER,
        )
        setattr(request, client_ip_attribute, client_ip)
    return getattr(request, client_ip_attribute)


def get_client_username(request):
    if settings.AXES_USERNAME_CALLABLE:
        return settings.AXES_USERNAME_CALLABLE(request)
    return request.POST.get(settings.AXES_USERNAME_FORM_FIELD, None)


def is_ipv6(ip):
    try:
        inet_pton(AF_INET6, ip)
    except (OSError, error):
        return False
    return True


def reset(ip=None, username=None):
    """Reset records that match ip or username, and
    return the count of removed attempts.
    """

    attempts = AccessAttempt.objects.all()
    if ip:
        attempts = attempts.filter(ip_address=ip)
    if username:
        attempts = attempts.filter(username=username)

    count, _ = attempts.delete()

    return count


def iso8601(timestamp):
    """Returns datetime.timedelta translated to ISO 8601 formatted duration.
    """
    seconds = timestamp.total_seconds()
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    date = '{:.0f}D'.format(days) if days else ''

    time_values = hours, minutes, seconds
    time_designators = 'H', 'M', 'S'

    time = ''.join([
        ('{:.0f}'.format(value) + designator)
        for value, designator in zip(time_values, time_designators)
        if value]
    )
    return 'P' + date + ('T' + time if time else '')


def get_lockout_message():
    if settings.AXES_COOLOFF_TIME:
        return settings.AXES_COOLOFF_MESSAGE
    return settings.AXES_PERMALOCK_MESSAGE
