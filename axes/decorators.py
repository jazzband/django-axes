from __future__ import unicode_literals

import json
import logging
from functools import wraps

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render

from axes import get_version
from axes.conf import settings
from axes.models import UserAccessFailureLog
from axes.utils import get_client_username
from axes.utils import get_lockout_message
from axes.utils import get_msg_code_by_priority
from axes.utils import is_m3_request


log = logging.getLogger(settings.AXES_LOGGER)
if settings.AXES_VERBOSE:
    log.info('AXES: BEGIN LOG')
    log.info('AXES: Using django-axes %s', get_version())
    if settings.AXES_ONLY_USER_FAILURES:
        log.info('AXES: blocking by username only.')
    elif settings.AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        log.info('AXES: blocking by combination of username and IP.')
    else:
        log.info('AXES: blocking by IP only.')

    if settings.AXES_FAILURE_LIMIT_MAX_BY_USER:
        log.info('AXES: Also blocking by username '
                 'if max tries by username reached.')


def axes_dispatch(func):
    def inner(request, *args, **kwargs):
        from axes.attempts import is_already_locked
        already_locked, context = is_already_locked(request)
        if already_locked:
            username = get_client_username(request)
            if settings.AXES_FAILURE_LIMIT_MAX_BY_USER:
                UserAccessFailureLog.create_or_update(username)
            return lockout_response(request, context)

        return func(request, *args, **kwargs)

    return inner


def axes_form_invalid(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        from axes.attempts import is_already_locked
        already_locked, context = is_already_locked(self.request)
        if already_locked:
            if settings.AXES_FAILURE_LIMIT_MAX_BY_USER:
                username = get_client_username(self.request)
                UserAccessFailureLog.create_or_update(username)
            return lockout_response(self.request, context)

        return func(self, *args, **kwargs)

    return inner


def lockout_response(request, context=None):
    # Special response for requests made by M3 platform
    if is_m3_request(request):
        try:
            from m3 import OperationResult
        except ImportError:
            raise Exception('Axes can\'t import m3.OperationResult.'
                      ' Make sure m3 is installed.')
        else:
            return OperationResult.by_message(
                str(get_lockout_message(request, context)))

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

    return HttpResponse(get_lockout_message(request, context), status=403)


def set_priority_message(func):
    """Decorator for "is_already_locked" function.
    Adds 'code', 'message' to context.

    From all code messages chooses the ONE
    that needs to be shown to user and adds to context.
    """
    @wraps(func)
    def inner(request, *args, **kwargs):
        already_blocked, context = func(request, *args, **kwargs)
        messages_codes = context.pop('messages_codes')
        message, code = get_msg_code_by_priority(messages_codes)
        context['message'] = message
        context['code'] = code
        return already_blocked, context

    return inner
