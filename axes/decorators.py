import logging
import socket

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.template.loader import get_template
from django.utils import timezone as datetime
from django.utils.translation import ugettext_lazy
from django.utils.ipv6 import clean_ipv6_address
from django.core.validators import validate_ipv4_address, validate_ipv6_address

try:
    from django.contrib.auth import get_user_model
except ImportError:  # django < 1.5
    from django.contrib.auth.models import User
else:
    User = get_user_model()

try:
    from django.contrib.auth.models import SiteProfileNotAvailable
except ImportError: # django >= 1.7
    SiteProfileNotAvailable = type('SiteProfileNotAvailable', (Exception,), {})

from axes.models import AccessLog
from axes.models import AccessAttempt
from axes.signals import user_locked_out
import axes
from django.utils import six


# see if the user has overridden the failure limit
FAILURE_LIMIT = getattr(settings, 'AXES_LOGIN_FAILURE_LIMIT', 3)

# see if the user has set axes to lock out logins after failure limit
LOCK_OUT_AT_FAILURE = getattr(settings, 'AXES_LOCK_OUT_AT_FAILURE', True)

USE_USER_AGENT = getattr(settings, 'AXES_USE_USER_AGENT', False)

# use a specific username field to retrieve from login POST data
USERNAME_FORM_FIELD = getattr(settings, 'AXES_USERNAME_FORM_FIELD', 'username')

# use a specific password field to retrieve from login POST data
PASSWORD_FORM_FIELD = getattr(settings, 'AXES_PASSWORD_FORM_FIELD', 'password')

# see if the django app is sitting behind a reverse proxy
BEHIND_REVERSE_PROXY = getattr(settings, 'AXES_BEHIND_REVERSE_PROXY', False)

# see if the django app is sitting behind a reverse proxy but can be accessed directly
BEHIND_REVERSE_PROXY_WITH_DIRECT_ACCESS = getattr(settings, 'AXES_BEHIND_REVERSE_PROXY_WITH_DIRECT_ACCESS', False)

# if the django app is behind a reverse proxy, look for the ip address using this HTTP header value
REVERSE_PROXY_HEADER = getattr(settings, 'AXES_REVERSE_PROXY_HEADER', 'HTTP_X_FORWARDED_FOR')

# lock out user from particular IP based on combination USER+IP
def should_lock_out_by_combination_user_and_ip():
    return getattr(settings, 'AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP', False)

COOLOFF_TIME = getattr(settings, 'AXES_COOLOFF_TIME', None)
if (isinstance(COOLOFF_TIME, int) or isinstance(COOLOFF_TIME, float) ):
    COOLOFF_TIME = timedelta(hours=COOLOFF_TIME)

LOGGER = getattr(settings, 'AXES_LOGGER', 'axes.watch_login')

LOCKOUT_TEMPLATE = getattr(settings, 'AXES_LOCKOUT_TEMPLATE', None)

# Deprecate this in favor of real log levels 
#VERBOSE = getattr(settings, 'AXES_VERBOSE', True)

# whitelist and blacklist
# todo: convert the strings to IPv4 on startup to avoid type conversion during processing
ONLY_WHITELIST = getattr(settings, 'AXES_ONLY_ALLOW_WHITELIST', False)
IP_WHITELIST = getattr(settings, 'AXES_IP_WHITELIST', None)
IP_BLACKLIST = getattr(settings, 'AXES_IP_BLACKLIST', None)

ERROR_MESSAGE = ugettext_lazy("Please enter a correct username and password. "
                              "Note that both fields are case-sensitive.")


log = logging.getLogger(LOGGER)

log.debug('AXES: BEGIN LOG')
log.debug('Using django-axes ' + axes.get_version())


if BEHIND_REVERSE_PROXY:
    log.debug('Axes is configured to be behind reverse proxy...looking for header value %s', REVERSE_PROXY_HEADER)


def get_ip_address_from_request(request):
    """ Makes the best attempt to get the client's real IP or return the loopback """
    
    # Would rather rely on middleware to set up a good REMOTE_ADDR than try to get
    # fancy here. Also, just use django's built in ipv4/ipv6 normalization logic
    ip_address = request.META.get('REMOTE_ADDR', 'bad address')
    try:
        validate_ipv4_address(ip_address)
    except:
        try:
            validate_ipv6_address(ip_address)
            ip_address = clean_ipv6_address(ip_address, True)
        except:
            log.error("Could not parse address {0}".format(ip_address))
            ip_address = "127.0.0.1"
        
    return ip_address


def get_ip(request):
    if not BEHIND_REVERSE_PROXY:
        ip = get_ip_address_from_request(request)
    else:
        ip = request.META.get(REVERSE_PROXY_HEADER, '')
        ip = ip.split(",", 1)[0].strip()
        if ip == '':
            if not BEHIND_REVERSE_PROXY_WITH_DIRECT_ACCESS:
                raise Warning('Axes is configured for operation behind a reverse proxy but could not find '\
                    'an HTTP header value {0}. Check your proxy server settings '\
                    'to make sure this header value is being passed.'.format(REVERSE_PROXY_HEADER))
            else:
                ip = request.META.get('REMOTE_ADDR', '')
                if not ip_in_whitelist(ip):
                    raise Warning('Axes is configured for operation behind a reverse proxy and to allow some'\
                        'IP addresses to have direct access. {0} is not on the white list'.format(ip))
    return ip


def get_lockout_url():
    return getattr(settings, 'AXES_LOCKOUT_URL', None)


def query2str(items, max_length=1024):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.

    The length of the output is limited to max_length to avoid a DoS attack via excessively large payloads.
    """
    # Would rather not store any query data in plaintext
    return ""
    #return '\n'.join(['%s=%s' % (k, v) for k, v in six.iteritems(items)
    #                  if k != PASSWORD_FORM_FIELD][:int(max_length/2)])[:max_length]


def ip_in_whitelist(ip):
    if IP_WHITELIST is not None:
        return ip in IP_WHITELIST

    return False


def ip_in_blacklist(ip):
    if IP_BLACKLIST is not None:
        return ip in IP_BLACKLIST

    return False


def is_user_lockable(request, username=None):
    """Check if the user has a profile with nolockout
    If so, then return the value to see if this user is special
    and doesn't get their account locked out
    """
    
    if username is None:
        username = request.POST.get(USERNAME_FORM_FIELD)
    
    try:
        field = getattr(User, 'USERNAME_FIELD', 'username')
        kwargs = {
            field: username
        }
        user = User.objects.get(**kwargs)
    except User.DoesNotExist:
        # not a valid user
        return True

    if hasattr(user, 'nolockout'):
        # need to invert since we need to return
        # false for users that can't be blocked
        return not user.nolockout

    elif hasattr(settings, 'AUTH_PROFILE_MODULE'):
        try:
            profile = user.get_profile()
            if hasattr(profile, 'nolockout'):
                # need to invert since we need to return
                # false for users that can't be blocked
                return not profile.nolockout

        except (SiteProfileNotAvailable, ObjectDoesNotExist, AttributeError):
            # no profile
            return True

    # Default behavior for a user to be lockable
    return True

def _get_user_attempts(request, username = None):
    """Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = get_ip(request)

    if username is None:
        username = request.POST.get(USERNAME_FORM_FIELD, None)

    if USE_USER_AGENT:
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
        if should_lock_out_by_combination_user_and_ip():
            params['username'] = username

        attempts = AccessAttempt.objects.filter(**params)

    return attempts

def get_user_attempts(request, username = None):
    objects_deleted = False
    attempts = _get_user_attempts(request, username)

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
        attempts = _get_user_attempts(request, username)

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
        if func.__name__ != 'decorated_login':
            log.debug('AXES: Calling decorated function: %s' % func.__name__)
            if args:
                log.debug('args: %s' % str(args))
            if kwargs:
                log.debug('kwargs: %s' % kwargs)

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

            access_log = AccessLog.objects.create(
                user_agent=request.META.get('HTTP_USER_AGENT', '<unknown>')[:255],
                ip_address=get_ip(request),
                username=request.POST.get(USERNAME_FORM_FIELD, None),
                http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
                path_info=request.META.get('PATH_INFO', '<unknown>'),
                trusted=not login_unsuccessful,
            )
            if check_request(request, login_unsuccessful):
                return response

            return lockout_response(request)

        return response

    return decorated_login


def lockout_response(request, username = None):
    if username is None:
        username = request.POST.get(USERNAME_FORM_FIELD, '')

    if LOCKOUT_TEMPLATE:
        context = {
            'cooloff_time': COOLOFF_TIME,
            'failure_limit': FAILURE_LIMIT,
            'username': username
        }
        template = get_template(LOCKOUT_TEMPLATE)
        content = template.render(context, request)
        return HttpResponse(content)

    LOCKOUT_URL = get_lockout_url()
    if LOCKOUT_URL:
        return HttpResponseRedirect(LOCKOUT_URL)

    if COOLOFF_TIME:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Please try again later.")
    else:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Contact an admin to unlock your account.")


def is_already_locked(request, username = None):

    ip = get_ip(request)

    if ONLY_WHITELIST:
        if not ip_in_whitelist(ip):
            return True

    if ip_in_blacklist(ip):
        return True

    user_lockable = is_user_lockable(request, username)

    if not user_lockable:
        return False

    attempts = get_user_attempts(request, username)

    for attempt in attempts:
        if attempt.failures_since_start >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE:
            return True

    return False


def check_request(request, login_unsuccessful, username=None):
    ip_address = get_ip(request)
    failures = 0
    
    if username is None:
        username = request.POST.get(USERNAME_FORM_FIELD, None)
        
    attempts = get_user_attempts(request, username)

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
                attempt.http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')
                attempt.path_info = request.META.get('PATH_INFO', '<unknown>')
                attempt.failures_since_start = failures
                attempt.attempt_time = datetime.now()
                attempt.save()
                log.info('AXES: Repeated login failure by %s. Updating access '
                         'record. Count = %s' %
                         (attempt.ip_address, failures))
        else:
            create_new_failure_records(request, failures, username)
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
            create_new_trusted_record(request, username)

    user_lockable = is_user_lockable(request, username)
    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if failures >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE and user_lockable:
        # We log them out in case they actually managed to enter the correct
        # password
        if hasattr(request, 'user') and request.user.is_authenticated():
            logout(request)
        log.warn('AXES: locked out %s after repeated login attempts.' %
                 (ip_address,))
        # send signal when someone is locked out.
        user_locked_out.send("axes", request=request, username=username, ip_address=ip_address)

        # if a trusted login has violated lockout, revoke trust
        for attempt in [a for a in attempts if a.trusted]:
            attempt.delete()
            create_new_failure_records(request, failures, username)

        return False

    return True


def create_new_failure_records(request, failures, username=None):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    
    if username is None:
        username = request.POST.get(USERNAME_FORM_FIELD, None)

    params = {
        'user_agent': ua,
        'ip_address': ip,
        'username': username,
        'get_data': query2str(request.GET),
        'post_data': query2str(request.POST),
        'http_accept': request.META.get('HTTP_ACCEPT', '<unknown>'),
        'path_info': request.META.get('PATH_INFO', '<unknown>'),
        'failures_since_start': failures,
    }

    AccessAttempt.objects.create(**params)

    log.info('AXES: New login failure by %s. Creating access record.' % (ip,))


def create_new_trusted_record(request, username=None):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    
    if username is None:
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
