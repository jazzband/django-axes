from __future__ import absolute_import

from django.contrib.auth.views import LoginView
from django.utils.decorators import method_decorator

from .decorators import axes_dispatch, axes_form_invalid


class AxesLoginMixin(object):
    @method_decorator(axes_dispatch)
    def dispatch(self, request, *args, **kwargs):
        return super(AxesLoginMixin, self).dispatch(request, *args, **kwargs)

    @method_decorator(axes_form_invalid)
    def form_invalid(self, form):
        return super(AxesLoginMixin, self).form_invalid(form)


class AxesLoginView(AxesLoginMixin, LoginView):
    pass
