.. _integration:

Integration
===========

Axes is intended to be pluggable and usable with custom authentication solutions.
This document describes the integration with some popular 3rd party packages
such as Django Allauth, Django REST Framework, and other tools.

In the following table
**Compatible** means that a component should be fully compatible out-of-the-box,
**Functional** means that a component should be functional after customization, and
**Incompatible** means that a component has been reported as non-functional with Axes.

=======================   =============   ============   ============   ==============
Project                   Version         Compatible     Functional     Incompatible
=======================   =============   ============   ============   ==============
Django REST Framework     |gte| 3.7.0     |check|
Django REST Framework     |lt| 3.7.0                     |check|
Django Allauth                                           |check|
Django Simple Captcha                                    |check|
Django OAuth Toolkit                                     |check|
Django Reversion                                         |check|
=======================   =============   ============   ============   ==============

.. |check|  unicode:: U+2713
.. |lt|     unicode:: U+003C
.. |lte|    unicode:: U+2264
.. |gte|    unicode:: U+2265
.. |gt|     unicode:: U+003E

Please note that project compatibility depends on multiple different factors
such as Django version, Axes version, and 3rd party package versions and
their unique combinations per project.

.. note::
   This documentation is mostly provided by Axes users.
   If you have your own compatibility tweaks and customizations
   that enable you to use Axes with other tools or have better
   implementations than the solutions provided here, please do
   feel free to open an issue or a pull request in GitHub!


Integration with Django Allauth
-------------------------------

Axes relies on having login information stored under ``AXES_USERNAME_FORM_FIELD`` key
both in ``request.POST`` and in ``credentials`` dict passed to
``user_login_failed`` signal.

This is not the case with Allauth. Allauth always uses the ``login`` key in post POST data
but it becomes ``username`` key in ``credentials`` dict in signal handler.

To overcome this you need to use custom login form that duplicates the value
of ``username`` key under a ``login`` key in that dict and set ``AXES_USERNAME_FORM_FIELD = 'login'``.

You also need to decorate ``dispatch()`` and ``form_invalid()`` methods of the Allauth login view.

``settings.py``::

    AXES_USERNAME_FORM_FIELD = 'login'

``example/forms.py``::

    from allauth.account.forms import LoginForm

    class AxesLoginForm(LoginForm):
        """
        Extended login form class that supplied the
        user credentials for Axes compatibility.
        """

        def user_credentials(self):
            credentials = super().user_credentials()
            credentials['login'] = credentials.get('email') or credentials.get('username')
            return credentials

``example/urls.py``::

    from django.utils.decorators import method_decorator

    from allauth.account.views import LoginView

    from axes.decorators import axes_dispatch
    from axes.decorators import axes_form_invalid

    from example.forms import AxesLoginForm

    LoginView.dispatch = method_decorator(axes_dispatch)(LoginView.dispatch)
    LoginView.form_invalid = method_decorator(axes_form_invalid)(LoginView.form_invalid)

    urlpatterns = [
        # Override allauth default login view with a patched view
        url(r'^accounts/login/$', LoginView.as_view(form_class=AxesLoginForm), name='account_login'),
        url(r'^accounts/', include('allauth.urls')),
    ]


Integration with Django REST Framework
--------------------------------------

.. note::
   Modern versions of Django REST Framework after 3.7.0 work normally with Axes
   out-of-the-box and require no customization in DRF.


Django REST Framework versions prior to 3.7.0
require the request object to be passed for authentication
by a customized DRF authentication class::

    from rest_framework.authentication import BasicAuthentication

    class AxesBasicAuthentication(BasicAuthentication):
        """
        Extended basic authentication backend class that supplies the
        request object into the authentication call for Axes compatibility.

        NOTE: This patch is only needed for DRF versions < 3.7.0.
        """

        def authenticate(self, request):
            # NOTE: Request is added as an instance attribute in here
            self._current_request = request
            return super().authenticate(request)

        def authenticate_credentials(self, userid, password, request=None):
            credentials = {
                get_user_model().USERNAME_FIELD: userid,
                'password': password
            }

            # NOTE: Request is added as an argument to the authenticate call here
            user = authenticate(request=request or self._current_request, **credentials)

            if user is None:
                raise exceptions.AuthenticationFailed(_('Invalid username/password.'))

            if not user.is_active:
                raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

            return (user, None)


Integration with Django Simple Captcha
--------------------------------------

Axes supports Captcha with the Django Simple Captcha package in the following manner.

``settings.py``::

    AXES_LOCKOUT_URL = '/locked'

``example/urls.py``::

    url(r'^locked/$', locked_out, name='locked_out'),

``example/forms.py``::

    class AxesCaptchaForm(forms.Form):
        captcha = CaptchaField()

``example/views.py``::

    from example.forms import AxesCaptchaForm

    def locked_out(request):
        if request.POST:
            form = AxesCaptchaForm(request.POST)
            if form.is_valid():
                ip = get_ip_address_from_request(request)
                reset(ip=ip)
                return HttpResponseRedirect(reverse_lazy('signin'))
        else:
            form = AxesCaptchaForm()

        return render_to_response('captcha.html', dict(form=form), context_instance=RequestContext(request))

``example/templates/example/captcha.html``::

    <form action="" method="post">
        {% csrf_token %}

        {{ form.captcha.errors }}
        {{ form.captcha }}

        <div class="form-actions">
            <input type="submit" value="Submit" />
        </div>
    </form>


Integration with Django OAuth Toolkit
-------------------------------------

Django OAuth toolkit is not designed to work with Axes,
but some users have reported that they have configured
validator classes to function correctly.


``example/validators.py``::

    from django.contrib.auth import authenticate
    from django.http import HttpRequest, QueryDict

    from oauth2_provider.oauth2_validators import OAuth2Validator

    from axes.helpers import get_client_ip_address, get_client_user_agent


    class AxesOAuth2Validator(OAuth2Validator):
        def validate_user(self, username, password, client, request, *args, **kwargs):
            """
            Check username and password correspond to a valid and active User

            Set defaults for necessary request object attributes for Axes compatibility.
            The ``request`` argument is not a Django ``HttpRequest`` object.
            """

            _request = request
            if request and not isinstance(request, HttpRequest):
                request = HttpRequest()

                request.uri = _request.uri
                request.method = request.http_method = _request.http_method
                request.META = request.headers = _request.headers
                request._params = _request._params
                request.decoded_body = _request.decoded_body

                request.axes_ip_address = get_client_ip_address(request)
                request.axes_user_agent = get_client_user_agent(request)

                body = QueryDict(str(_request.body), mutable=True)
                if request.method == 'GET':
                    request.GET = body
                elif request.method == 'POST':
                    request.POST = body

            user = authenticate(request=request, username=username, password=password)
            if user is not None and user.is_active:
                request = _request
                request.user = user
                return True

            return False


``settings.py``::

    OAUTH2_PROVIDER = {
        'OAUTH2_VALIDATOR_CLASS': 'example.validators.AxesOAuth2Validator',
        'SCOPES': {'read': 'Read scope', 'write': 'Write scope'},
    }


Integration with Django Reversion
---------------------------------

Django Reversion is not designed to work with Axes,
but some users have reported that they have configured
a workaround with a monkeypatch function that functions correctly.

``example/monkeypatch.py``::

    from django.urls import resolve

    from reversion import views

    def _request_creates_revision(request):
        view_name = resolve(request.path_info).url_name
        if view_name and view_name.endswith('login'):
            return False

        return request.method not in ["OPTIONS", "GET", "HEAD"]

    views._request_creates_revision = _request_creates_revision
