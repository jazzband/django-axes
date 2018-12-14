from __future__ import unicode_literals

from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from axes.attempts import is_already_locked
from axes.utils import get_lockout_message


class AxesModelBackend(ModelBackend):

    class RequestParameterRequired(Exception):
        msg = 'AxesModelBackend requires calls to authenticate to pass `request` as an argument.'

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

        already_locked, context = is_already_locked(request)
        if already_locked:
            # locked out, don't try to authenticate, just update return_context and return
            # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.
            error_msg = get_lockout_message(request, context)
            response_context = kwargs.get('response_context', {})
            response_context['error'] = error_msg

            # FIXME: If ANY attempts for username
            #   need to be counted (valid and invalid) on
            #   AXES_FAILURE_LIMIT_MAX_BY_USER, then uncomment the code below.

            # username = get_client_username(request)
            # if settings.AXES_FAILURE_LIMIT_MAX_BY_USER:
            #     UserAccessFailureLog.create_or_update(username)
            raise PermissionDenied(error_msg)

        # No-op
