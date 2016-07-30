Django Axes
===========

.. image:: https://jazzband.co/static/img/badge.svg
   :target: https://jazzband.co/
   :alt: Jazzband

.. image:: https://secure.travis-ci.org/jazzband/django-axes.png?branch=master
    :target: http://travis-ci.org/jazzband/django-axes
    :alt: Build Status

``django-axes`` is a very simple way for you to keep track of failed login
attempts, both for the Django admin and for the rest of your site. The name is
sort of a geeky pun, since ``axes`` can be read interpreted as:

* "access", as in monitoring access attempts
* "axes", as in tools you can use hack (generally on wood). In this case,
  however, the "hacking" part of it can be taken a bit further: ``django-axes``
  is intended to help you *stop* people from hacking (popular media
  definition) your website. Hilarious, right? That's what I thought too!


For more information see the documentation at:

https://django-axes.readthedocs.io/

If you have questions or have trouble using the app please file a bug report
at:

https://github.com/jazzband/django-axes/issues


Requirements
============

``django-axes`` requires a supported Django version. The application is
intended to work around the Django admin and the regular
``django.contrib.auth`` login-powered pages.
Look at https://www.djangoproject.com/download/ to check if your version
is supported.

Development
===========

You can contribute to this project forking it from github and sending pull requests.

Running tests
-------------

Clone the repository and install the django version you want. Then run::

    $ ./runtests.py

Issues
======

Not being locked out after failed attempts
------------------------------------------

You may find that Axes is not capturing your failed login attempts. It may
be that you need to manually add watch_login to your login url.

For example, in your urls.py::

    ...
    from my.custom.app import login
    from axes.decorators import watch_login
    ...
    urlpatterns = patterns('',
        (r'^login/$', watch_login(login)),
    ...


Locked out without reason
-------------------------

It may happen that you have suddenly become locked out without a single failed
attempt. One possible reason is that you are using some custom login form and the
username field is named something different than "username", e.g. "email". This
leads to all users attempts being lumped together. To fix this add the following
to your settings:

    AXES_USERNAME_FORM_FIELD = "email"


Using a captcha
===============

Using https://github.com/mbi/django-simple-captcha you do the following:

1. Change axes lockout url in ``settings.py``::

    AXES_LOCKOUT_URL = '/locked'

2. Add the url in ``urls.py``::

    url(r'^locked/$', locked_out, name='locked_out'),

3. Create a captcha form::

    class AxesCaptchaForm(forms.Form):
        captcha = CaptchaField()

4. Create a captcha view for the above url that resets on captcha success and redirects::

    def locked_out(request):
        if request.POST:
            form = AxesCaptchaForm(request.POST)
            if form.is_valid():
                ip = get_ip_address_from_request(request)
                reset(ip=ip)
                return HttpResponseRedirect(reverse_lazy('signin'))
        else:
            form = AxesCaptchaForm()

        return render_to_response('locked_out.html', dict(form=form), context_instance=RequestContext(request))

5. Add a captcha template::

    <form action="" method="post">
        {% csrf_token %}

        {{ form.captcha.errors }}
        {{ form.captcha }}

        <div class="form-actions">
            <input type="submit" value="Submit" />
        </div>
    </form>

Done.
