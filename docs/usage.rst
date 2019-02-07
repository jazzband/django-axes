.. _usage:

Usage
=====

``django-axes`` listens to signals from ``django.contrib.auth.signals`` to
log access attempts:

* ``user_logged_in``
* ``user_logged_out``
* ``user_login_failed``

You can also use ``django-axes`` with your own auth module, but you'll need
to ensure that it sends the correct signals in order for ``django-axes`` to
log the access attempts.

Quickstart
----------

Once ``axes`` is in your ``INSTALLED_APPS`` in your project settings file, you can
login and logout of your application via the ``django.contrib.auth`` views.
The attempts will be logged and visible in the "Access Attempts" section in admin.

By default, Axes will lock out repeated access attempts from the same IP address.
You can allow this IP to attempt again by deleting relevant ``AccessAttempt`` records.

Records can be deleted, for example, by using the Django admin application.

You can also use the ``axes_reset``, ``axes_reset_ip``, and ``axes_reset_user``
management commands with the Django ``manage.py`` command helpers:

* ``manage.py axes_reset`` will reset all lockouts and access records.
* ``manage.py axes_reset_ip ip [ip ...]``
  will clear lockouts and records for the given IP addresses.
* ``manage.py axes_reset_user username [username ...]``
  will clear lockouts and records for the given usernames.

In your code, you can use the ``axes.utils.reset`` function.

* ``reset()`` will reset all lockouts and access records.
* ``reset(ip=ip)`` will clear lockouts and records for the given IP address.
* ``reset(username=username)`` will clear lockouts and records for the given username.

Example usage
-------------

Here is a more detailed example of sending the necessary signals using
`django-axes` and a custom auth backend at an endpoint that expects JSON
requests. The custom authentication can be swapped out with ``authenticate``
and ``login`` from ``django.contrib.auth``, but beware that those methods take
care of sending the nessary signals for you, and there is no need to duplicate
them as per the example.

*forms.py:* ::

    from django import forms

    class LoginForm(forms.Form):
        username = forms.CharField(max_length=128, required=True)
        password = forms.CharField(max_length=128, required=True)

*views.py:* ::

    from django.http import JsonResponse, HttpResponse
    from django.utils.decorators import method_decorator
    from django.contrib.auth import signals
    from django.views import View
    from django.views.decorators.csrf import csrf_exempt

    from axes.decorators import axes_dispatch

    from myapp.forms import LoginForm
    from myapp.auth import custom_authenticate, custom_login


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

            user = custom_authenticate(
                request=request,
                username=form.cleaned_data.get('username'),
                password=form.cleaned_data.get('password'),
            )

            if user is not None:
                custom_login(request, user)

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

*urls.py:* ::

    from django.urls import path
    from myapp.views import Login

    urlpatterns = [
        path('login/', Login.as_view(), name='login'),
    ]

Integration with django-allauth
-------------------------------

``axes`` relies on having login information stored under ``AXES_USERNAME_FORM_FIELD`` key
both in ``request.POST`` and in ``credentials`` dict passed to
``user_login_failed`` signal. This is not the case with ``allauth``.
``allauth`` always uses ``login`` key in post POST data but it becomes ``username``
key in ``credentials`` dict in signal handler.

To overcome this you need to use custom login form that duplicates the value
of ``username`` key under a ``login`` key in that dict
(and set ``AXES_USERNAME_FORM_FIELD = 'login'``).

You also need to decorate ``dispatch()`` and ``form_invalid()`` methods
of the ``allauth`` login view. By default ``axes`` is patching only the
``LoginView`` from ``django.contrib.auth`` app and with ``allauth`` you have to
do the patching of views yourself.

*settings.py:* ::

    AXES_USERNAME_FORM_FIELD = 'login'

*forms.py:* ::

    from allauth.account.forms import LoginForm

    class AllauthCompatLoginForm(LoginForm):
        def user_credentials(self):
            credentials = super(AllauthCompatLoginForm, self).user_credentials()
            credentials['login'] = credentials.get('email') or credentials.get('username')
            return credentials

*urls.py:* ::

    from allauth.account.views import LoginView
    from axes.decorators import axes_dispatch
    from axes.decorators import axes_form_invalid
    from django.utils.decorators import method_decorator

    from my_app.forms import AllauthCompatLoginForm

    LoginView.dispatch = method_decorator(axes_dispatch)(LoginView.dispatch)
    LoginView.form_invalid = method_decorator(axes_form_invalid)(LoginView.form_invalid)

    urlpatterns = [
        # ...
        url(r'^accounts/login/$', # Override allauth's default view with a patched view
            LoginView.as_view(form_class=AllauthCompatLoginForm),
            name="account_login"),
        url(r'^accounts/', include('allauth.urls')),
        # ...
    ]

Altering username before login
------------------------------

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

*settings.py:* ::

    def sample_username_modifier(request):
        provided_username = request.POST.get('username')
        some_namespace = request.POST.get('namespace')
        return '-'.join([some_namespace, provided_username[9:]])

    AXES_USERNAME_CALLABLE = sample_username_modifier

    # New format that can also be used
    # the credentials argument is provided if the
    # function signature has two arguments instead of one

    def sample_username_modifier_credentials(request, credentials):
        provided_username = credentials.get('username')
        some_namespace = credentials.get('namespace')
        return '-'.join([some_namespace, provided_username[9:]])

    AXES_USERNAME_CALLABLE = sample_username_modifier_new

NOTE: You still have to make these modifications yourself before calling
authenticate. If you want to re-use the same function for consistency, that's
fine, but ``axes`` doesn't inject these changes into the authentication flow
for you.
