from socket import inet_pton, AF_INET6, error

from django.core.cache import cache
from django.utils import six

from axes.attempts import get_cache_key
from axes.conf import settings
from axes.models import AccessAttempt


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
    count = 0

    attempts = AccessAttempt.objects.all()
    if ip:
        attempts = attempts.filter(ip_address=ip)
    if username:
        attempts = attempts.filter(username=username)

    if attempts:
        count = attempts.count()
        for attempt in attempts:
            cache_hash_key = get_cache_key(attempt)
            if cache.get(cache_hash_key):
                cache.delete(cache_hash_key)

        attempts.delete()
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
