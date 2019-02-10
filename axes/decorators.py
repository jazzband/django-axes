from functools import wraps

from axes.attempts import is_already_locked
from axes.utils import get_lockout_response


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
