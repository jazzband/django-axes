from django.conf import settings
from django.contrib.auth import logout
from axes.models import AccessAttempt
from django.http import HttpResponse
import axes
import datetime
import logging
from django.core.cache import cache

# see if the user has overridden the failure limit
if hasattr(settings, 'AXES_LOGIN_FAILURE_LIMIT'):
    FAILURE_LIMIT = settings.LOGIN_FAILURE_LIMIT
else:
    FAILURE_LIMIT = 3

# see if the user has set axes to lock out logins after failure limit
if hasattr(settings, 'AXES_LOCK_OUT_AT_FAILURE'):
    LOCK_OUT_AT_FAILURE = settings.AXES_LOCK_OUT_AT_FAILURE
else:
    LOCK_OUT_AT_FAILURE = True

if hasattr(settings, 'AXES_USE_USER_AGENT'):
    USE_USER_AGENT = settings.AXES_USE_USER_AGENT
else:
    USE_USER_AGENT = False

if hasattr(settings, 'AXES_COOLOFF_TIME'):
    COOLOFF_TIME = settings.AXES_COOLOFF_TIME
    if isinstance(COOLOFF_TIME, int):
        COOLOFF_TIME = datetime.timedelta(hours=COOLOFF_TIME)
else:
    COOLOFF_TIME = None

def query2str(items):
    return '\n'.join(['%s=%s' % (k, v) for k,v in items])

log = logging.getLogger('axes.watch_login')
log.info('BEGIN LOG')
log.info('Using django-axes ' + axes.get_version())

def get_user_attempt(request):
    """
    Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = request.META.get('REMOTE_ADDR', '')
    if USE_USER_AGENT:
        ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        attempts = AccessAttempt.objects.filter(
            user_agent=ua,
            ip_address=ip
        )
    else:
        attempts = AccessAttempt.objects.filter(
            ip_address=ip
        )
    if not attempts:
        return None
    attempt = attempts[0]
    if COOLOFF_TIME:
        if attempt.attempt_time + COOLOFF_TIME < datetime.datetime.now():
            attempt.delete()
            return None
    return attempt

def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login':
            log.info('Calling decorated function: %s' % func)
            if args: log.info('args: %s' % args)
            if kwargs: log.info('kwargs: %s' % kwargs)

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
            failures = 0
            # see if the login was successful
            login_unsuccessful = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )
            attempt = get_user_attempt(request)
            
            if attempt:
                failures = attempt.failures_since_start

            if login_unsuccessful:
                # add a failed attempt for this user
                failures += 1
                log.info('-' * 79)

            # Create an AccessAttempt record if the login wasn't successful
            if login_unsuccessful:
                # has already attempted, update the info
                if attempt:
                    log.info('=================================')
                    log.info('Updating access attempt record...')
                    log.info('=================================')
                    attempt.get_data = '%s\n---------\n%s' % (
                        attempt.get_data,
                        query2str(request.GET.items()),
                    )
                    attempt.post_data = '%s\n---------\n%s' % (
                        attempt.post_data,
                        query2str(request.POST.items())
                    )
                    attempt.http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')
                    attempt.path_info = request.META.get('PATH_INFO', '<unknown>')
                    attempt.failures_since_start = failures
                    attempt.attempt_time = datetime.datetime.now()
                    attempt.save()
                else:
                    log.info('=================================')
                    log.info('Creating access attempt record...')
                    log.info('=================================')
                    ip = request.META.get('REMOTE_ADDR', '')
                    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
                    attempt = AccessAttempt.objects.create(
                        user_agent=ua,
                        ip_address=ip,
                        get_data=query2str(request.GET.items()),
                        post_data=query2str(request.POST.items()),
                        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
                        path_info=request.META.get('PATH_INFO', '<unknown>'),
                        failures_since_start=failures
                    )

            # no matter what, we want to lock them out
            # if they're past the number of attempts allowed
            if failures > FAILURE_LIMIT:
                if LOCK_OUT_AT_FAILURE:
                    if COOLOFF_TIME:
                        response = HttpResponse("Account locked: too many login attempts.  "
                                                "Please try again later."
                                                )
                    else:
                        response = HttpResponse("Account locked: too many login attempts.  "
                                                "Contact an admin to unlock your account."
                                                 )
                    # We log them out in case they actually managed to enter
                    # the correct password.
                    logout(request)

        return response
    return decorated_login
