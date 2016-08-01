.. _captcha:

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

