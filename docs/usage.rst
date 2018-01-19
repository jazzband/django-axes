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

Once ``axes`` is in your ``INSTALLED_APPS`` in your project settings file,
you can login and logout of your application via the ``django.contrib.auth``
views. The access attempts will be logged and visible in the "Access Attempts"
secion of the admin app.

By default, django-axes will lock out repeated attempts from the same IP
address. You can allow this IP to attempt again by deleting the relevant
``AccessAttempt`` records in the admin.

You can also use the ``axes_reset`` management command using Django's
``manage.py``.

* ``manage.py axes_reset`` will reset all lockouts and access records.
* ``manage.py axes_reset ip`` will clear lockout/records for ip

In your code, you can use ``from axes.utils import reset``.

* ``reset()`` will reset all lockouts and access records.
* ``reset(ip=ip)`` will clear lockout/records for ip
* ``reset(username=username)`` will clear lockout/records for a username

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

    from django.views.decorators.csrf import csrf_exempt
    from django.utils.decorators import method_decorator
    from django.http import JsonResponse, HttpResponse
    from django.contrib.auth.signals import user_logged_in,\
        user_logged_out,\
        user_login_failed
    import json
    from myapp.forms import LoginForm
    from myapp.auth import custom_authenticate, custom_login

    @method_decorator(csrf_exempt, name='dispatch')
    class Login(View):
        ''' Custom login view that takes JSON credentials '''

        http_method_names = ['post',]

        def post(self, request):
            # decode post json to dict & validate
            post_data = json.loads(request.body.decode('utf-8'))
            form = LoginForm(post_data)

            if not form.is_valid():
                # inform axes of failed login
                user_login_failed.send(
                    sender = User,
                    request = request,
                    credentials = {
                        'username': form.cleaned_data.get('username')
                    }
                )
                return HttpResponse(status=400)
            user = custom_authenticate(
                request = request,
                username = form.cleaned_data.get('username'),
                password = form.cleaned_data.get('password'),
            ) 

            if user is not None:
                custom_login(request, user)
                user_logged_in.send(
                    sender = User,
                    request = request,
                    user = user,
                )
                return JsonResponse({'message':'success!'}, status=200)
            else:
                user_login_failed.send(
                    sender = User,
                    request = request,
                    credentials = {
                        'username':form.cleaned_data.get('username')
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
