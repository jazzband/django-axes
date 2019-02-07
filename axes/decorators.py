from functools import wraps
import logging

from axes import get_version
from axes.conf import settings
from axes.attempts import is_already_locked
from axes.utils import get_lockout_response

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


def axes_dispatch(func):
    def inner(request, *args, **kwargs):
        if is_already_locked(request):
            return get_lockout_response(request)

        return func(request, *args, **kwargs)

    return inner


def axes_form_invalid(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        if is_already_locked(self.request):
            return get_lockout_response(self.request)

        return func(self, *args, **kwargs)

    return inner
