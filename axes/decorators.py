try:
    from functools import wraps
except ImportError:
    from django.utils.functional import wraps  # Python 2.4 fallback.

from datetime import timedelta
import logging

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django import http
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django import template
from django.template import RequestContext
from django.utils.translation import ugettext_lazy, ugettext as _

# Use the timezone support in Django >= 1.4 if it's available.
try:
    from django.utils import timezone as datetime
except ImportError:
    # Fallback for Django < 1.4.
    from datetime import datetime

from axes.models import AccessAttempt, AccessLog
from axes.signals import user_locked_out
import axes

# see if the user has overridden the failure limit
FAILURE_LIMIT = getattr(settings, 'AXES_LOGIN_FAILURE_LIMIT', 3)

# see if the user has set axes to lock out logins after failure limit
LOCK_OUT_AT_FAILURE = getattr(settings, 'AXES_LOCK_OUT_AT_FAILURE', True)

USE_USER_AGENT = getattr(settings, 'AXES_USE_USER_AGENT', False)

#see if the django app is sitting behind a reverse proxy 
BEHIND_REVERSE_PROXY = getattr(settings, 'AXES_BEHIND_REVERSE_PROXY', False)
#if the django app is behind a reverse proxy, look for the ip address using this HTTP header value
REVERSE_PROXY_HEADER = getattr(settings, 'AXES_REVERSE_PROXY_HEADER', 'HTTP_X_FORWARDED_FOR')


COOLOFF_TIME = getattr(settings, 'AXES_COOLOFF_TIME', None)
if isinstance(COOLOFF_TIME, int):
    COOLOFF_TIME = timedelta(hours=COOLOFF_TIME)

LOGGER = getattr(settings, 'AXES_LOGGER', 'axes.watch_login')

LOCKOUT_TEMPLATE = getattr(settings, 'AXES_LOCKOUT_TEMPLATE', None)
VERBOSE = getattr(settings, 'AXES_VERBOSE', True)

# whitelist and blacklist
# todo: convert the strings to IPv4 on startup to avoid type conversion during processing
ONLY_WHITELIST = getattr(settings, 'AXES_ONLY_ALLOW_WHITELIST', False)
IP_WHITELIST = getattr(settings, 'AXES_IP_WHITELIST', None)
IP_BLACKLIST = getattr(settings, 'AXES_IP_BLACKLIST', None)

ERROR_MESSAGE = ugettext_lazy("Please enter a correct username and password. "
                              "Note that both fields are case-sensitive.")
LOGIN_FORM_KEY = 'this_is_the_login_form'


def get_ip(request):
    if not BEHIND_REVERSE_PROXY:
        ip = request.META.get('REMOTE_ADDR', '')
    else:
        logging.debug('Axes is configured to be behind reverse proxy...looking for header value %s', REVERSE_PROXY_HEADER)
        ip = request.META.get(REVERSE_PROXY_HEADER, '')
        if ip == '':
            raise Warning('Axes is configured for operation behind a reverse proxy but could not find '\
                          'an HTTP header value {0}. Check your proxy server settings '\
                          'to make sure this header value is being passed.'.format(REVERSE_PROXY_HEADER))
    return ip

def get_lockout_url():
    return getattr(settings, 'AXES_LOCKOUT_URL', None)


def query2str(items):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.
    """

    kvs = []
    for k, v in items:
        if k != 'password':
            kvs.append(u'%s=%s' % (k, v))

    return '\n'.join(kvs)


def ip_in_whitelist(ip):
    if IP_WHITELIST is not None:
        return ip in IP_WHITELIST
    else:
        return False


def ip_in_blacklist(ip):
    if IP_BLACKLIST is not None:
        return ip in IP_BLACKLIST
    else:
        return False


log = logging.getLogger(LOGGER)
if VERBOSE:
    log.info('AXES: BEGIN LOG')
    log.info('Using django-axes ' + axes.get_version())

def is_user_lockable(request):
    """ Check if the user has a profile with nolockout
    If so, then return the value to see if this user is special
    and doesn't get their account locked out """
    username = request.POST.get('username', None)
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        # not a valid user
        return True
    try:
        profile = user.get_profile()
    except:
        # no profile
        return True

    if hasattr(profile, 'nolockout'):
        # need to revert since we need to return
        # false for users that can't be blocked
        return not profile.nolockout
    else:
        return True

def get_user_attempts(request):
    """
    Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = get_ip(request)
        
    username = request.POST.get('username', None)

    if USE_USER_AGENT:
        ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        attempts = AccessAttempt.objects.filter(
            user_agent=ua, ip_address=ip, username=username, trusted=True
        )
    else:
        attempts = AccessAttempt.objects.filter(
            ip_address=ip, username=username, trusted=True
        )

    if len(attempts) == 0:
        params = {'ip_address': ip, 'trusted': False}
        if USE_USER_AGENT:
            params['user_agent'] = ua

        attempts = AccessAttempt.objects.filter(**params)
        if username and not ip_in_whitelist(ip):
            del params['ip_address']
            params['username'] = username
            attempts |= AccessAttempt.objects.filter(**params)

    if COOLOFF_TIME:
        for attempt in attempts:
            if attempt.attempt_time + COOLOFF_TIME < datetime.now() \
               and attempt.trusted is False:
                attempt.delete()

    return attempts


def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login' and VERBOSE:
            log.info('AXES: Calling decorated function: %s' % func.__name__)
            if args:
                log.info('args: %s' % args)
            if kwargs:
                log.info('kwargs: %s' % kwargs)

        # TODO: create a class to hold the attempts records and perform checks
        # with its methods? or just store attempts=get_user_attempts here and
        # pass it to the functions
        # also no need to keep accessing these:
        # ip = request.META.get('REMOTE_ADDR', '')
        # ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        # username = request.POST.get('username', None)

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
            log_access_request(request, login_unsuccessful)
            if check_request(request, login_unsuccessful):
                return response

            return lockout_response(request)
        return response

    return decorated_login


def lockout_response(request):
    if LOCKOUT_TEMPLATE:
        context = {
            'cooloff_time': COOLOFF_TIME,
            'failure_limit': FAILURE_LIMIT,
        }
        return render_to_response(LOCKOUT_TEMPLATE, context,
                                  context_instance=RequestContext(request))

    LOCKOUT_URL = get_lockout_url()
    if LOCKOUT_URL:
        return HttpResponseRedirect(LOCKOUT_URL)

    if COOLOFF_TIME:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Please try again later.")
    else:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Contact an admin to unlock your account.")


def is_already_locked(request):
    ip = get_ip(request)

    if ONLY_WHITELIST:
        if not ip_in_whitelist(ip):
            return True

    if ip_in_blacklist(ip):
        return True

    attempts = get_user_attempts(request)
    user_lockable = is_user_lockable(request)
    for attempt in attempts:
        if attempt.failures_since_start >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE and user_lockable:
            return True

    return False


def log_access_request(request, login_unsuccessful):
    """ Log the access attempt """
    access_log = AccessLog()
    access_log.user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')
    access_log.ip_address = get_ip(request)
    access_log.username = request.POST.get('username', None)
    access_log.http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')
    access_log.path_info = request.META.get('PATH_INFO', '<unknown>')
    access_log.trusted = not login_unsuccessful
    access_log.save()


def check_request(request, login_unsuccessful):
    ip_address = get_ip(request)
    username = request.POST.get('username', None)
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
                    query2str(request.GET.items()),
                )
                attempt.post_data = '%s\n---------\n%s' % (
                    attempt.post_data,
                    query2str(request.POST.items())
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

    user_lockable = is_user_lockable(request)
    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if failures >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE and user_lockable:
        # We log them out in case they actually managed to enter the correct
        # password
        logout(request)
        log.warn('AXES: locked out %s after repeated login attempts.' %
                 (ip_address,))
        # send signal when someone is locked out.
        user_locked_out.send("axes", request=request, username=username, ip_address=ip_address)

        # if a trusted login has violated lockout, revoke trust
        for attempt in [a for a in attempts if a.trusted]:
            attempt.delete()
            create_new_failure_records(request, failures)

        return False

    return True


def create_new_failure_records(request, failures):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
    username = request.POST.get('username', None)

    params = {
        'user_agent': ua,
        'ip_address': ip,
        'username': None,
        'get_data': query2str(request.GET.items()),
        'post_data': query2str(request.POST.items()),
        'http_accept': request.META.get('HTTP_ACCEPT', '<unknown>'),
        'path_info': request.META.get('PATH_INFO', '<unknown>'),
        'failures_since_start': failures,
    }

    # record failed attempt from this IP
    AccessAttempt.objects.create(**params)

    # record failed attempt on this username from untrusted IP
    params.update({
        'ip_address': None,
        'username': username,
    })
    AccessAttempt.objects.create(**params)

    log.info('AXES: New login failure by %s. Creating access record.' % (ip,))


def create_new_trusted_record(request):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
    username = request.POST.get('username', None)

    if not username:
        return False

    AccessAttempt.objects.create(
        user_agent=ua,
        ip_address=ip,
        username=username,
        get_data=query2str(request.GET.items()),
        post_data=query2str(request.POST.items()),
        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
        path_info=request.META.get('PATH_INFO', '<unknown>'),
        failures_since_start=0,
        trusted=True
    )


def _display_login_form(request, error_message=''):
    request.session.set_test_cookie()
    return render_to_response('admin/login.html', {
        'title': _('Log in'),
        'app_path': request.get_full_path(),
        'error_message': error_message
    }, context_instance=template.RequestContext(request))


def staff_member_required(view_func):
    """
    Decorator for views that checks that the user is logged in and is a staff
    member, displaying the login page if necessary.  Mostly quoted from
    django.contrib.auth.decorators.staff_member_required.  License for
    Django-extracted code follows:

    Copyright (c) Django Software Foundation and individual contributors.  All
    rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright
           notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright
           notice, this list of conditions and the following disclaimer in the
           documentation and/or other materials provided with the distribution.

        3. Neither the name of Django nor the names of its contributors may be
           used to endorse or promote products derived from this software
           without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE."""

    def _checklogin(request, *args, **kwargs):
        if request.user.is_active and request.user.is_staff:
            # The user is valid. Continue to the admin page.
            return view_func(request, *args, **kwargs)

        assert hasattr(request, 'session'), "The Django admin requires session middleware to be installed. Edit your MIDDLEWARE_CLASSES setting to insert 'django.contrib.sessions.middleware.SessionMiddleware'."

        # If this isn't already the login page, display it.
        if LOGIN_FORM_KEY not in request.POST:
            if request.POST:
                message = _("Please log in again, because your session has expired.")
            else:
                message = ""
            return _display_login_form(request, message)

        # Check that the user accepts cookies.
        if not request.session.test_cookie_worked():
            message = _("Looks like your browser isn't configured to accept cookies. Please enable cookies, reload this page, and try again.")
            return _display_login_form(request, message)
        else:
            request.session.delete_test_cookie()

        # Check the password.
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        user = authenticate(username=username, password=password)
        # next two lines are where this differs from django's
        # @staff_member_required -- ready?
        if not check_request(request, not user):
            return lockout_response(request)
        if user is None:
            message = ERROR_MESSAGE
            if '@' in username:
                # Mistakenly entered e-mail address instead of username? Look it up.
                users = list(User.objects.filter(email=username))
                if len(users) == 1 and users[0].check_password(password):
                    message = _("Your e-mail address is not your username. Try '%s' instead.") % users[0].username
                else:
                    # Either we cannot find the user, or if more than 1
                    # we cannot guess which user is the correct one.
                    message = _("Usernames cannot contain the '@' character.")
            return _display_login_form(request, message)

        # The user data is correct; log in the user in and continue.
        else:
            if user.is_active and user.is_staff:
                login(request, user)
                return http.HttpResponseRedirect(request.get_full_path())
            else:
                return _display_login_form(request, ERROR_MESSAGE)

    return wraps(view_func)(_checklogin)
