.. _integration:

Integration
===========

Axes is intended to be pluggable and usable with custom authentication solutions.
This document describes the integration with some popular 3rd party packages
such as Django Allauth, Django REST Framework, and other tools.

In the following table
**Compatible** means that a component should be fully compatible out-of-the-box,
**Functional** means that a component should be functional after configuration, and
**Incompatible** means that a component has been reported as non-functional with Axes.

=======================   =============   ============   ============   ==============
Project                   Version         Compatible     Functional     Incompatible
=======================   =============   ============   ============   ==============
Django REST Framework                                    |check|
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
        path('accounts/login/', LoginView.as_view(form_class=AxesLoginForm), name='account_login'),
        path('accounts/', include('allauth.urls')),
    ]


Integration with Django REST Framework
--------------------------------------

Django Axes requires REST Framework to be connected
via lockout signals for correct functionality.

You can use the following snippet in your project signals such as ``example/signals.py``::

    from django.dispatch import receiver

    from axes.signals import user_locked_out
    from rest_framework.exceptions import PermissionDenied


    @receiver(user_locked_out)
    def raise_permission_denied(*args, **kwargs):
        raise PermissionDenied("Too many failed login attempts")

And then configure your application to load it in ``examples/apps.py``::

    from django import apps


    class AppConfig(apps.AppConfig):
        name = "example"

        def ready(self):
            from example import signals  # noqa

Please check the Django signals documentation for more information:

https://docs.djangoproject.com/en/3.1/topics/signals/

When a user login fails a signal is emitted and PermissionDenied
raises a HTTP 403 reply which interrupts the login process.

This functionality was handled in the middleware for a time,
but that resulted in extra database requests being made for
each and every web request, and was migrated to signals.


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

    from axes.utils import reset_request
    from django.http.response import HttpResponseRedirect
    from django.shortcuts import render
    from django.urls import reverse_lazy

    from .forms import AxesCaptchaForm


    def locked_out(request):
        if request.POST:
            form = AxesCaptchaForm(request.POST)
            if form.is_valid():
                reset_request(request)
                return HttpResponseRedirect(reverse_lazy('auth_login'))
        else:
            form = AxesCaptchaForm()

        return render(request, 'accounts/captcha.html', {'form': form})

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
