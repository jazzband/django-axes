import json
import logging

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render

from axes import get_version
from axes import settings as axes_settings
from axes.attempts import is_already_locked
from axes.utils import iso8601
from axes.signals import *      # load all signals


log = logging.getLogger(axes_settings.LOGGER)
if axes_settings.VERBOSE:
    log.info('AXES: BEGIN LOG')
    log.info('AXES: Using django-axes ' + get_version())
    if axes_settings.ONLY_USER_FAILURES:
        log.info('AXES: blocking by username only.')
    elif axes_settings.LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        log.info('AXES: blocking by combination of username and IP.')
    else:
        log.info('AXES: blocking by IP only.')


if axes_settings.BEHIND_REVERSE_PROXY:
    log.debug('AXES: Axes is configured to be behind reverse proxy')
    log.debug(
        'AXES: Looking for header value %s', axes_settings.REVERSE_PROXY_HEADER
    )
    log.debug(
        'AXES: Number of proxies configured: {} '
        '(please check this if you are using a custom header)'.format(
            axes_settings.NUM_PROXIES
        )
    )


def log_decorated_call(func, args=None, kwargs=None):
    log.info('AXES: Calling decorated function: %s' % func.__name__)
    if args:
        log.info('args: %s' % str(args))
    if kwargs:
        log.info('kwargs: %s' % kwargs)


def watch_login(func):
    # Don't decorate multiple times
    if func.__name__ == 'decorated_dispatch':
        return func

    def decorated_dispatch(LoginView, request, *args, **kwargs):
        if func.__name__ != 'decorated_dispatch' and axes_settings.VERBOSE:
            log_decorated_call(func, args, kwargs)

        # If the request is currently under lockout, do not proceed to the
        # login function, go directly to lockout url, do not pass go, do not
        # collect messages about this login attempt
        if is_already_locked(request):
            return lockout_response(request)

        # call the login function
        return func(LoginView, request, *args, **kwargs)

    return decorated_dispatch


def lockout_response(request):
    context = {
        'failure_limit': axes_settings.FAILURE_LIMIT,
        'username': request.POST.get(axes_settings.USERNAME_FORM_FIELD, '')
    }

    if request.is_ajax():
        if axes_settings.COOLOFF_TIME:
            context.update({
                'cooloff_time': iso8601(axes_settings.COOLOFF_TIME)
            })

        return HttpResponse(
            json.dumps(context),
            content_type='application/json',
            status=403,
        )

    elif axes_settings.LOCKOUT_TEMPLATE:
        if axes_settings.COOLOFF_TIME:
            context.update({
                'cooloff_time': iso8601(axes_settings.COOLOFF_TIME)
            })

        return render(
            request, axes_settings.LOCKOUT_TEMPLATE, context, status=403
        )

    elif axes_settings.LOCKOUT_URL:
        return HttpResponseRedirect(axes_settings.LOCKOUT_URL)

    else:
        msg = 'Account locked: too many login attempts. {0}'
        if axes_settings.COOLOFF_TIME:
            msg = msg.format('Please try again later.')
        else:
            msg = msg.format('Contact an admin to unlock your account.')

        return HttpResponse(msg, status=403)
