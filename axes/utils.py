from socket import inet_pton, AF_INET6, error

from django.core.cache import cache
from django.utils import six

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


def get_ip(request):
    """Parse IP address from REMOTE_ADDR or
    AXES_REVERSE_PROXY_HEADER if AXES_BEHIND_REVERSE_PROXY is set."""
    if settings.AXES_BEHIND_REVERSE_PROXY:
        # For requests originating from behind a reverse proxy,
        # resolve the IP address from the given AXES_REVERSE_PROXY_HEADER.
        # AXES_REVERSE_PROXY_HEADER defaults to HTTP_X_FORWARDED_FOR,
        # which is the Django name for the HTTP X-Forwarder-For header.
        # Please see RFC7239 for additional information:
        #   https://tools.ietf.org/html/rfc7239#section-5

        # The REVERSE_PROXY_HEADER HTTP header is a list
        # of potentionally unsecure IPs, for example:
        #   X-Forwarded-For: 1.1.1.1, 11.11.11.11:8080, 111.111.111.111
        ip_str = request.META.get(settings.AXES_REVERSE_PROXY_HEADER, '')

        # We need to know the number of proxies present in the request chain
        # in order to securely calculate the one IP that is the real client IP.
        #
        # This is because IP headers can have multiple IPs in different
        # configurations, with e.g. the X-Forwarded-For header containing
        # the originating client IP, proxies and possibly spoofed values.
        #
        # If you are using a special header for client calculation such as the
        # X-Real-IP or the like with nginx, please check this configuration.
        #
        # Please see discussion for more information:
        #   https://github.com/jazzband/django-axes/issues/224
        ip_list = [ip.strip() for ip in ip_str.split(',')]

        # Pick the nth last IP in the given list of addresses after parsing
        if len(ip_list) >= settings.AXES_NUM_PROXIES:
            ip = ip_list[-settings.AXES_NUM_PROXIES]

            # Fix IIS adding client port number to the
            # 'X-Forwarded-For' header (strip port)
            if not is_ipv6(ip):
                ip = ip.split(':', 1)[0]

        # If nth last is not found, default to no IP and raise a warning
        else:
            ip = ''
            raise Warning(
                'AXES: Axes is configured for operation behind a '
                'reverse proxy but received too few IPs in the HTTP '
                'AXES_REVERSE_PROXY_HEADER. Check your '
                'AXES_NUM_PROXIES configuration. '
                'Header name: {0}, value: {1}'.format(
                    settings.AXES_REVERSE_PROXY_HEADER, ip_str
                )
            )

        if not ip:
            raise Warning(
                'AXES: Axes is configured for operation behind a reverse '
                'proxy but could not find a suitable IP in the specified '
                'HTTP header. Check your proxy server settings to make '
                'sure correct headers are being passed to Django in '
                'AXES_REVERSE_PROXY_HEADER. '
                'Header name: {0}, value: {1}'.format(
                    settings.AXES_REVERSE_PROXY_HEADER, ip_str
                )
            )

        return ip

    return request.META.get('REMOTE_ADDR', '')


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
        # import should be here to avoid circular dependency with get_ip
        from axes.attempts import get_cache_key
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
