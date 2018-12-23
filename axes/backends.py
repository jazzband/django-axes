from __future__ import unicode_literals

from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from axes.attempts import is_already_locked
from axes.utils import get_credentials, get_lockout_message


class AxesModelBackend(ModelBackend):

    class RequestParameterRequired(Exception):
        msg = 'AxesModelBackend requires calls to authenticate to pass `request` as an argument.'

        def __init__(self):
            super(AxesModelBackend.RequestParameterRequired, self).__init__(
                AxesModelBackend.RequestParameterRequired.msg)

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Checks user lock out status and raises PermissionDenied if user is not allowed to log in.

        Inserts errors directly to `return_context` that is supplied as a keyword argument.

        Use this on top of your AUTHENTICATION_BACKENDS list to prevent locked out users
        from being authenticated in the standard Django authentication flow.

        Note that this method does not log your user in and delegates login to other backends.

        :param request: see ModelBackend.authenticate
        :param kwargs: see ModelBackend.authenticate
        :keyword response_context: context dict that will be updated with error information
        :raises PermissionDenied: if user is already locked out
        :return: None
        """

        if request is None:
            raise AxesModelBackend.RequestParameterRequired()

        credentials = get_credentials(username=username, password=password, **kwargs)

        if is_already_locked(request, credentials):
            # locked out, don't try to authenticate, just update return_context and return
            # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.
            error_msg = get_lockout_message()
            response_context = kwargs.get('response_context', {})
            response_context['error'] = error_msg
            raise PermissionDenied(error_msg)

        # No-op
