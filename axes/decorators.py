import json
import logging
from socket import inet_pton, AF_INET6, error

from django.contrib.auth import get_user_model
from django.contrib.auth import logout
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import six
from django.utils import timezone as datetime

from axes.models import AccessAttempt
from axes.models import AccessLog
from axes.settings import *
from axes.signals import user_locked_out
from axes.utils import iso8601
import axes

log = logging.getLogger(LOGGER)
if VERBOSE:
    log.info('AXES: BEGIN LOG')
    log.info('Using django-axes ' + axes.get_version())


if BEHIND_REVERSE_PROXY:
    log.debug('Axes is configured to be behind reverse proxy')
    log.debug('Looking for header value %s', REVERSE_PROXY_HEADER)


def is_ipv6(ip):
    try:
        inet_pton(AF_INET6, ip)
    except (OSError, error):
        return False
    return True


def get_ip(request):
    """Parse IP address from REMOTE_ADDR or
    AXES_REVERSE_PROXY_HEADER if AXES_BEHIND_REVERSE_PROXY is set."""

    if BEHIND_REVERSE_PROXY:
        # For requests originating from behind a reverse proxy,
        # resolve the IP address from the given AXES_REVERSE_PROXY_HEADER.
        # AXES_REVERSE_PROXY_HEADER defaults to HTTP_X_FORWARDED_FOR if not given,
        # which is the Django calling format for the HTTP X-Forwarder-For header.
        # Please see RFC7239 for additional information:
        #   https://tools.ietf.org/html/rfc7239#section-5

        ip = request.META.get(REVERSE_PROXY_HEADER, '')

        if not ip:
            raise Warning(
                'Axes is configured for operation behind a reverse proxy '
                'but could not find an HTTP header value. Check your proxy '
                'server settings to make sure this header value is being '
                'passed. Header value {0}'.format(REVERSE_PROXY_HEADER)
            )

        # X-Forwarded-For IPs can have multiple IPs of which the first one is the
        # originating reverse and the rest are proxies that are between the client
        ip = ip.split(',', 1)[0]

        # As spaces are permitted between given X-Forwarded-For IP addresses, strip them as well
        ip = ip.strip()

        # Fix IIS adding client port number to 'X-Forwarded-For' header (strip port)
        if not is_ipv6(ip):
            ip = ip.split(':', 1)[0]

        return ip

    return request.META.get('REMOTE_ADDR', '')


def query2str(items, max_length=1024):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.

    The length of the output is limited to max_length to avoid a DoS attack
    via excessively large payloads.
    """
    return '\n'.join([
        '%s=%s' % (k, v) for k, v in six.iteritems(items)
        if k != PASSWORD_FORM_FIELD
    ][:int(max_length / 2)])[:max_length]


def ip_in_whitelist(ip):
    if IP_WHITELIST is not None:
        return ip in IP_WHITELIST

    return False


def ip_in_blacklist(ip):
    if IP_BLACKLIST is not None:
        return ip in IP_BLACKLIST

    return False


def is_user_lockable(request):
    """Check if the user has a profile with nolockout
    If so, then return the value to see if this user is special
    and doesn't get their account locked out
    """
    if hasattr(request.user, 'nolockout'):
        return not request.user.nolockout

    if request.method != 'POST':
        return True

    try:
        field = getattr(get_user_model(), 'USERNAME_FIELD', 'username')
        kwargs = {
            field: request.POST.get(USERNAME_FORM_FIELD)
        }
        user = get_user_model().objects.get(**kwargs)

        if hasattr(user, 'nolockout'):
            # need to invert since we need to return
            # false for users that can't be blocked
            return not user.nolockout

    except get_user_model().DoesNotExist:
        # not a valid user
        return True

    # Default behavior for a user to be lockable
    return True


def _get_user_attempts(request):
    """Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = get_ip(request)
    username = request.POST.get(USERNAME_FORM_FIELD, None)

    if AXES_ONLY_USER_FAILURES:
        attempts = AccessAttempt.objects.filter(username=username)
    elif USE_USER_AGENT:
        ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
        attempts = AccessAttempt.objects.filter(
            user_agent=ua, ip_address=ip, username=username, trusted=True
        )
    else:
        attempts = AccessAttempt.objects.filter(
            ip_address=ip, username=username, trusted=True
        )

    if not attempts:
        params = {'ip_address': ip, 'trusted': False}
        if USE_USER_AGENT:
            params['user_agent'] = ua
        if LOCK_OUT_BY_COMBINATION_USER_AND_IP:
            params['username'] = username

        attempts = AccessAttempt.objects.filter(**params)

    return attempts


def get_user_attempts(request):
    objects_deleted = False
    attempts = _get_user_attempts(request)

    if COOLOFF_TIME:
        for attempt in attempts:
            if attempt.attempt_time + COOLOFF_TIME < datetime.now():
                if attempt.trusted:
                    attempt.failures_since_start = 0
                    attempt.save()
                else:
                    attempt.delete()
                    objects_deleted = True

    # If objects were deleted, we need to update the queryset to reflect this,
    # so force a reload.
    if objects_deleted:
        attempts = _get_user_attempts(request)

    return attempts


def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    # Don't decorate multiple times
    if func.__name__ == 'decorated_login':
        return func

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login' and VERBOSE:
            log.info('AXES: Calling decorated function: %s' % func.__name__)
            if args:
                log.info('args: %s' % str(args))
            if kwargs:
                log.info('kwargs: %s' % kwargs)

        # TODO: create a class to hold the attempts records and perform checks
        # with its methods? or just store attempts=get_user_attempts here and
        # pass it to the functions
        # also no need to keep accessing these:
        # ip = request.META.get('REMOTE_ADDR', '')
        # ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        # username = request.POST.get(USERNAME_FORM_FIELD, None)

        # if the request is currently under lockout, do not proceed to the
        # login function, go directly to lockout url, do not pass go, do not
        # collect messages about this login attempt
        if is_already_locked(request):
            return lockout_response(request)

        # call the login function
        response = func(request, *args, **kwargs)

        if func.__name__ == 'decorated_login':
            # if we're dealing with this function itself, don't bother checking
            # for invalid login attempts.  I suppose there's a bunch of
            # recursion going on here that used to cause one failed login
            # attempt to generate 10+ failed access attempt records (with 3
            # failed attempts each supposedly)
            return response

        if request.method == 'POST':
            # see if the login was successful
            login_unsuccessful = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )

            user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
            http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
            path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
            if not DISABLE_ACCESS_LOG:
                if login_unsuccessful or not DISABLE_SUCCESS_ACCESS_LOG:
                    AccessLog.objects.create(
                        user_agent=user_agent,
                        ip_address=get_ip(request),
                        username=request.POST.get(USERNAME_FORM_FIELD, None),
                        http_accept=http_accept,
                        path_info=path_info,
                        trusted=not login_unsuccessful,
                    )
            if check_request(request, login_unsuccessful):
                return response

            return lockout_response(request)

        return response

    return decorated_login


def lockout_response(request):
    context = {
        'failure_limit': FAILURE_LIMIT,
        'username': request.POST.get(USERNAME_FORM_FIELD, '')
    }

    if request.is_ajax():
        if COOLOFF_TIME:
            context.update({'cooloff_time': iso8601(COOLOFF_TIME)})

        return HttpResponse(
            json.dumps(context),
            content_type='application/json',
            status=403,
        )

    elif LOCKOUT_TEMPLATE:
        if COOLOFF_TIME:
            context.update({'cooloff_time': iso8601(COOLOFF_TIME)})

        return render(request, LOCKOUT_TEMPLATE, context, status=403)

    elif LOCKOUT_URL:
        return HttpResponseRedirect(LOCKOUT_URL)

    else:
        msg = 'Account locked: too many login attempts. {0}'
        if COOLOFF_TIME:
            msg = msg.format('Please try again later.')
        else:
            msg = msg.format('Contact an admin to unlock your account.')

        return HttpResponse(msg, status=403)


def is_already_locked(request):
    ip = get_ip(request)

    if NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip):
        return False

    if ONLY_WHITELIST and not ip_in_whitelist(ip):
        return True

    if ip_in_blacklist(ip):
        return True

    if not is_user_lockable(request):
        return False

    for attempt in get_user_attempts(request):
        if attempt.failures_since_start >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE:
            return True

    return False


def check_request(request, login_unsuccessful):
    ip_address = get_ip(request)
    username = request.POST.get(USERNAME_FORM_FIELD, None)
    failures = 0
    attempts = get_user_attempts(request)

    for attempt in attempts:
        failures = max(failures, attempt.failures_since_start)

    if login_unsuccessful:
        # add a failed attempt for this user
        failures += 1

        # Create an AccessAttempt record if the login wasn't successful
        # has already attempted, update the info
        if len(attempts):
            for attempt in attempts:
                attempt.get_data = '%s\n---------\n%s' % (
                    attempt.get_data,
                    query2str(request.GET),
                )
                attempt.post_data = '%s\n---------\n%s' % (
                    attempt.post_data,
                    query2str(request.POST)
                )
                attempt.http_accept = \
                    request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
                attempt.path_info = \
                    request.META.get('PATH_INFO', '<unknown>')[:255]
                attempt.failures_since_start = failures
                attempt.attempt_time = datetime.now()
                attempt.save()
                log.info(
                    'AXES: Repeated login failure by %s. Updating access '
                    'record. Count = %s' % (attempt.ip_address, failures)
                )
        else:
            create_new_failure_records(request, failures)
    else:
        # user logged in -- forget the failed attempts
        failures = 0
        trusted_record_exists = False
        for attempt in attempts:
            if not attempt.trusted:
                attempt.delete()
            else:
                trusted_record_exists = True
                attempt.failures_since_start = 0
                attempt.save()

        if trusted_record_exists is False:
            create_new_trusted_record(request)

    if NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip_address):
        return True

    user_lockable = is_user_lockable(request)
    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if failures >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE and user_lockable:
        # We log them out in case they actually managed to enter the correct
        # password
        if hasattr(request, 'user') and request.user.is_authenticated():
            logout(request)
        log.warn(
            'AXES: locked out %s after repeated login attempts.' % ip_address
        )
        # send signal when someone is locked out.
        user_locked_out.send(
            'axes', request=request, username=username, ip_address=ip_address
        )

        # if a trusted login has violated lockout, revoke trust
        for attempt in [a for a in attempts if a.trusted]:
            attempt.delete()
            create_new_failure_records(request, failures)

        return False

    return True


def create_new_failure_records(request, failures):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    username = request.POST.get(USERNAME_FORM_FIELD, None)

    # record failed attempt from this IP if not AXES_ONLY_USER_FAILURES
    if not AXES_ONLY_USER_FAILURES:
        AccessAttempt.objects.create(
            user_agent=ua,
            ip_address=ip,
            username=username,
            get_data=query2str(request.GET),
            post_data=query2str(request.POST),
            http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
            path_info=request.META.get('PATH_INFO', '<unknown>'),
            failures_since_start=failures,
        )
        log.info('AXES: New login failure by %s. Creating access record.' % (ip,))


def create_new_trusted_record(request):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    username = request.POST.get(USERNAME_FORM_FIELD, None)

    if not username:
        return False

    AccessAttempt.objects.create(
        user_agent=ua,
        ip_address=ip,
        username=username,
        get_data=query2str(request.GET),
        post_data=query2str(request.POST),
        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
        path_info=request.META.get('PATH_INFO', '<unknown>'),
        failures_since_start=0,
        trusted=True
    )
