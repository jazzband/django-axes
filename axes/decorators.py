from datetime import timedelta
from functools import wraps
import json
import logging

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render

from axes import get_version
from axes.conf import settings
from axes.attempts import is_already_locked
from axes.utils import iso8601


log = logging.getLogger(settings.AXES_LOGGER)
if settings.AXES_VERBOSE:
    log.info('AXES: BEGIN LOG')
    log.info('AXES: Using django-axes ' + get_version())
    if settings.AXES_ONLY_USER_FAILURES:
        log.info('AXES: blocking by username only.')
    elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        log.info('AXES: blocking by combination of username and IP.')
    else:
        log.info('AXES: blocking by IP only.')


def axes_dispatch(func):
    def inner(request, *args, **kwargs):
        if is_already_locked(request):
            return lockout_response(request)

        return func(request, *args, **kwargs)

    return inner


def axes_form_invalid(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        if is_already_locked(self.request):
            return lockout_response(self.request)

        return func(self, *args, **kwargs)

    return inner


def lockout_response(request):
    context = {
        'failure_limit': settings.AXES_FAILURE_LIMIT,
        'username': request.POST.get(settings.AXES_USERNAME_FORM_FIELD, '')
    }

    cool_off = settings.AXES_COOLOFF_TIME
    if cool_off:
        if (isinstance(cool_off, int) or isinstance(cool_off, float)):
            cool_off = timedelta(hours=cool_off)

        context.update({
            'cooloff_time': iso8601(cool_off)
        })

    if request.is_ajax():
        return HttpResponse(
            json.dumps(context),
            content_type='application/json',
            status=403,
        )

    elif settings.AXES_LOCKOUT_TEMPLATE:
        return render(
            request, settings.AXES_LOCKOUT_TEMPLATE, context, status=403
        )

    elif settings.AXES_LOCKOUT_URL:
        return HttpResponseRedirect(settings.AXES_LOCKOUT_URL)

    else:
        msg = 'Account locked: too many login attempts. {0}'
        if settings.AXES_COOLOFF_TIME:
            msg = msg.format('Please try again later.')
        else:
            msg = msg.format('Contact an admin to unlock your account.')

        return HttpResponse(msg, status=403)
