from __future__ import unicode_literals

import datetime
import logging

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


log = logging.getLogger(settings.AXES_LOGGER)


def get_axes_cache():
    return caches[getattr(settings, 'AXES_CACHE', 'default')]


def get_axes_cool_off(cool_off):
    """cool_off is a datetime.timedelta object
    You can provide custom callable for formatting the cool_off
    output that end user will see.

    default: iso8601
    """
    formatter = settings.AXES_COOLOFF_TIME_FORMATTER_CALLABLE
    if formatter:
        return formatter(cool_off)
    return iso8601(cool_off)


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
    # Additional option to support 'username' field from headers
    username_field = request.META.get('AXES_USERNAME_FORM_FIELD')
    if username_field:
        return request.POST.get(username_field, None)

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


def get_lockout_message(request, context=None):
    """Creates message that user will see on
    failing login.
    """

    if context is None:
        return ''

    context.update({
        'failure_limit': settings.AXES_FAILURE_LIMIT,
        'failure_limit_by_user': settings.AXES_FAILURE_LIMIT_MAX_BY_USER,
        'username': get_client_username(request) or ''
    })

    cool_off = settings.AXES_COOLOFF_TIME
    if cool_off:
        if isinstance(cool_off, (int, float)):
            cool_off = datetime.timedelta(hours=cool_off)

        context.update({
            'cooloff_time': get_axes_cool_off(cool_off),
        })

    log.debug('Msg code: %d' % context.get('code'))
    msg = context.pop('message')
    str_msg = msg.format(**context)
    # log.debug('Msg description: %s' % str_msg)

    return str_msg


def is_m3_request(request):
    """Checks if request is made by M3 platform."""
    return request.META.get('AXES_PLATFORM') == 'M3'


def get_msg_code_by_priority(message_codes):
    """Returns tuple of top ONE message and code
    from message_codes.

    Since method "is_already_locked" generates many message codes,
    but only one of them (message) eventually needs to be shown to user,
    we need a way to define which one.

    PRIORITY is a priority order for codes. The greater index,
    the higher priority.

    If message_codes is empty -  ('', None)
    Logs error if code not found in PRIORITY
    or no description found in AXES_MESSAGE_CODE_DESC_MAP setting.
    """

    if not message_codes:
        return '', None

    PRIORITY = [
        1001,
        1011,
        1002,
        1010,
        1003,
        1009,
        1004,
        1005,
        1006,
        1007,
        1008,
    ]

    message_codes = list(set(message_codes))

    not_in_priority_exist = [x for x in message_codes if x not in PRIORITY]
    if not_in_priority_exist:
        log.error(
            'Message codes not in priority list: {}.'
            ' Add them to the list.'.format(not_in_priority_exist)
        )
        return '', None

    max_rated_index = PRIORITY.index(message_codes[0])
    for code in message_codes:
        current_index = PRIORITY.index(code)
        if current_index > max_rated_index:
            max_rated_index = current_index

    message_code = PRIORITY[max_rated_index]
    try:
        return settings.AXES_MESSAGE_CODE_DESC_MAP[message_code], message_code
    except KeyError:
        log.error(
            'Message code does {} not have a description related to it.'
            ' Add description to settings.MESSAGE_CODE_DESC_MAP.'
                .format(not_in_priority_exist)
        )
        return '', None
