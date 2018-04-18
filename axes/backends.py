from __future__ import unicode_literals

from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from axes.attempts import is_already_locked
from axes.utils import get_lockout_message


class AxesModelBackend(ModelBackend):

    class RequestParameterRequired(Exception):
        msg = 'DjangoAxesModelBackend requires calls to authenticate to pass `request`'

        def __init__(self):
            super(AxesModelBackend.RequestParameterRequired, self).__init__(
                AxesModelBackend.RequestParameterRequired.msg)

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Add django-axes handling and add allow adding errors directly to a passed return_context.
        Will never actually authenticate a user, just blocks locked out uses so don't use this as your only back end.
        :param request: see ModelBackend.authenticate
        :param username: see ModelBackend.authenticate
        :param password: see ModelBackend.authenticate
        :keyword response_context: context dict that will be returned/used in the response template.
            NOTE: will overwrite 'error' field in dict
        :param kwargs: see ModelBackend.authenticate
        :raises PermissionDenied: if user is already locked out.
        :return: Nothing, but will update return_context with lockout message if user is locked out.
        """

        if request is None:
            raise AxesModelBackend.RequestParameterRequired()

        if is_already_locked(request):
            # locked out, don't try to authenticate, just update return_context and return
            # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.
            error_msg = get_lockout_message()
            response_context = kwargs.get('response_context', {})
            response_context['error'] = error_msg
            raise PermissionDenied(error_msg)

        # No-op
