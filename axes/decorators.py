try:
    from functools import wraps
except ImportError:
    from django.utils.functional import wraps  # Python 2.4 fallback.

from datetime import datetime, timedelta
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

from axes.models import AccessAttempt
import axes

# see if the user has overridden the failure limit
FAILURE_LIMIT = getattr(settings, 'AXES_LOGIN_FAILURE_LIMIT', 3)

# see if the user has set axes to lock out logins after failure limit
LOCK_OUT_AT_FAILURE = getattr(settings, 'AXES_LOCK_OUT_AT_FAILURE', True)

USE_USER_AGENT = getattr(settings, 'AXES_USE_USER_AGENT', False)

COOLOFF_TIME = getattr(settings, 'AXES_COOLOFF_TIME', None)
if isinstance(COOLOFF_TIME, int):
    COOLOFF_TIME = timedelta(hours=COOLOFF_TIME)

LOGGER = getattr(settings, 'AXES_LOGGER', 'axes.watch_login')

LOCKOUT_TEMPLATE = getattr(settings, 'AXES_LOCKOUT_TEMPLATE', None)
LOCKOUT_URL = getattr(settings, 'AXES_LOCKOUT_URL', None)
VERBOSE = getattr(settings, 'AXES_VERBOSE', True)

def query2str(items):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.
    """

    kvs = []
    for k, v in items:
        if k != 'password':
            kvs.append(u'%s=%s' % (k, v))

    return '\n'.join(kvs)

log = logging.getLogger(LOGGER)
if VERBOSE:
    log.info('AXES: BEGIN LOG')
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
    if COOLOFF_TIME and attempt.attempt_time + COOLOFF_TIME < datetime.now():
        attempt.delete()
        return None

    return attempt

def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login' and VERBOSE:
            log.info('AXES: Calling decorated function: %s' % func.__name__)
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
            # see if the login was successful
            login_unsuccessful = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )
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
                                  context_instance = RequestContext(request))

    if LOCKOUT_URL:
        return HttpResponseRedirect(LOCKOUT_URL)

    if COOLOFF_TIME:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Please try again later.")
    else:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Contact an admin to unlock your account.")

def check_request(request, login_unsuccessful):
    failures = 0
    attempt = get_user_attempt(request)

    if attempt:
        failures = attempt.failures_since_start

    # no matter what, we want to lock them out
    # if they're past the number of attempts allowed
    if failures > FAILURE_LIMIT and LOCK_OUT_AT_FAILURE:
        # We log them out in case they actually managed to enter
        # the correct password.
        logout(request)
        log.warn('AXES: locked out %s after repeated login attempts.' %
                 attempt.ip_address)
        return False

    if login_unsuccessful:
        # add a failed attempt for this user
        failures += 1

        # Create an AccessAttempt record if the login wasn't successful
        # has already attempted, update the info
        if attempt:
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
            log.info('AXES: New login failure by %s. Creating access record.' %
                     ip)
    else:
        # user logged in -- forget the failed attempts
        if attempt:
            attempt.delete()

    return True

ERROR_MESSAGE = ugettext_lazy("Please enter a correct username and password. Note that both fields are case-sensitive.")
LOGIN_FORM_KEY = 'this_is_the_login_form'

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
           used to endorse or promote products derived from this software without
           specific prior written permission.

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
