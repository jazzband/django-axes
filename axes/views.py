from __future__ import absolute_import

from django.contrib.auth.views import LoginView

from axes.attempts import is_already_locked
from .decorators import lockout_response


class AxesLoginMixin(object):
    def dispatch(self, request, *args, **kwargs):
        if is_already_locked(request):
            return lockout_response(request)

        return super(AxesLoginMixin, self).dispatch(request, *args, **kwargs)

    def form_invalid(self, form):
        if is_already_locked(self.request):
            return lockout_response(self.request)

        return super(AxesLoginMixin, self).form_invalid(form)


class AxesLoginView(AxesLoginMixin, LoginView):
    pass
