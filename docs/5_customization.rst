.. customization:

Customization
=============

Axes has multiple options for customization including customizing the
attempt tracking and lockout handling logic and lockout response formatting.

There are public APIs and the whole Axes tracking system is pluggable.
You can swap the authentication backend, attempt tracker, failure handlers,
database or cache backends and error formatters as you see fit.

Check the API reference section for further inspiration on
implementing custom authentication backends, middleware, and handlers.

Axes uses the stock Django signals for login monitoring and
can be customized and extended by using them correctly.

Axes listens to the following signals from ``django.contrib.auth.signals`` to log access attempts:

* ``user_logged_in``
* ``user_logged_out``
* ``user_login_failed``

You can also use Axes with your own auth module, but you'll need
to ensure that it sends the correct signals in order for Axes to
log the access attempts.


Customizing authentication views
--------------------------------

Here is a more detailed example of sending the necessary signals using
and a custom auth backend at an endpoint that expects JSON
requests. The custom authentication can be swapped out with ``authenticate``
and ``login`` from ``django.contrib.auth``, but beware that those methods take
care of sending the necessary signals for you, and there is no need to duplicate
them as per the example.

``example/forms.py``::

    from django import forms

    class LoginForm(forms.Form):
        username = forms.CharField(max_length=128, required=True)
        password = forms.CharField(max_length=128, required=True)

``example/views.py``::

    from django.contrib.auth import signals
    from django.http import JsonResponse, HttpResponse
    from django.utils.decorators import method_decorator
    from django.views import View
    from django.views.decorators.csrf import csrf_exempt

    from axes.decorators import axes_dispatch

    from example.forms import LoginForm
    from example.authentication import authenticate, login


    @method_decorator(axes_dispatch, name='dispatch')
    @method_decorator(csrf_exempt, name='dispatch')
    class Login(View):
        """
        Custom login view that takes JSON credentials
        """

        http_method_names = ['post']

        def post(self, request):
            form = LoginForm(request.POST)

            if not form.is_valid():
                # inform django-axes of failed login
                signals.user_login_failed.send(
                    sender=User,
                    request=request,
                    credentials={
                        'username': form.cleaned_data.get('username'),
                    },
                )
                return HttpResponse(status=400)

            user = authenticate(
                request=request,
                username=form.cleaned_data.get('username'),
                password=form.cleaned_data.get('password'),
            )

            if user is not None:
                login(request, user)

                signals.user_logged_in.send(
                    sender=User,
                    request=request,
                    user=user,
                )

                return JsonResponse({
                    'message':'success'
                }, status=200)

            # inform django-axes of failed login
            signals.user_login_failed.send(
                sender=User,
                request=request,
                credentials={
                    'username': form.cleaned_data.get('username'),
                },
            )

            return HttpResponse(status=403)

``urls.py``::

    from django.urls import path
    from example.views import Login

    urlpatterns = [
        path('login/', Login.as_view(), name='login'),
    ]


Customizing username lookups
----------------------------

In special cases, you may have the need to modify the username that is
submitted before attempting to authenticate. For example, adding namespacing or
removing client-set prefixes. In these cases, ``axes`` needs to know how to make
these changes so that it can correctly identify the user without any form
cleaning or validation. This is where the ``AXES_USERNAME_CALLABLE`` setting
comes in. You can define how to make these modifications in a callable that
takes a request object and a credentials dictionary,
and provide that callable to ``axes`` via this setting.

For example, a function like this could take a post body with something like
``username='prefixed-username'`` and ``namespace=my_namespace`` and turn it
into ``my_namespace-username``:

``example/utils.py``::

    def get_username(request, credentials):
        username = credentials.get('username')
        namespace = credentials.get('namespace')
        return namespace + '-' + username

``settings.py``::

    AXES_USERNAME_CALLABLE = 'example.utils.get_username'

.. note::
   You still have to make these modifications yourself before calling
   authenticate. If you want to re-use the same function for consistency, that's
   fine, but Axes does not inject these changes into the authentication flow
   for you.

Customizing lockout responses
-----------------------------

Axes can be configured with ``AXES_LOCKOUT_CALLABLE`` to return a custom lockout response when using the plugin with e.g. DRF (Django REST Framework) or other third party libraries which require specialized formats such as JSON or XML response formats or customized response status codes.

An example of usage could be e.g. a custom view for processing lockouts.

``example/views.py``::

    from django.http import JsonResponse

    def lockout(request, credentials, *args, **kwargs):
        return JsonResponse({"status": "Locked out due to too many login failures"}, status=403)

``settings.py``::

    AXES_LOCKOUT_CALLABLE = "example.views.lockout"

.. _customizing-lockout-parameters:

Customizing lockout parameters
------------------------------

Axes can be configured with ``AXES_LOCKOUT_PARAMETERS`` to lock out users not only by IP address.

``AXES_LOCKOUT_PARAMETERS`` can be a list of strings (which represents a separate lockout parameter) or nested lists of strings (which represents lockout parameters used in combination) or a callable which accepts HttpRequest or AccessAttempt and credentials and returns a list of the same form as described earlier.

Example ``AXES_LOCKOUT_PARAMETERS`` configuration:

``settings.py``::

    AXES_LOCKOUT_PARAMETERS = ["ip_address", ["username", "user_agent"]]

This way, axes will lock out users using ip_address and/or combination of username and user agent

Example of callable ``AXES_LOCKOUT_PARAMETERS``:

``example/utils.py``::

    from django.http import HttpRequest

    def get_lockout_parameters(request_or_attempt, credentials):

        if isinstance(request_or_attempt, HttpRequest):
           is_localhost = request.META.get("REMOTE_ADDR") == "127.0.0.1"

        else:
           is_localhost = request_or_attempt.ip_address == "127.0.0.1"
        
        if is_localhost:
           return ["username"] 
        
        return ["ip_address", "username"]

``settings.py``::

    AXES_LOCKOUT_CALLABLE = "example.utils.get_lockout_parameters"

This way, if client ip_address is localhost, axes will lockout client only by username. In other case, axes will lockout client by username and/or ip_address.

Customizing client ip address lookups
-------------------------------------

Axes can be configured with ``AXES_CLIENT_IP_CALLABLE`` to use custom client ip address lookup logic.

``example/utils.py``::

    def get_client_ip(request):
        return request.META.get("REMOTE_ADDR")

``settings.py``::

    AXES_LOCKOUT_CALLABLE = "example.utils.get_client_ip"
