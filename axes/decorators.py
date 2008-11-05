from axes.models import AccessAttempt
from django.conf import settings

# see if the user has overridden the failure limit
if hasattr(settings, 'LOGIN_FAILURE_LIMIT'):
    FAILURE_LIMIT = settings.LOGIN_FAILURE_LIMIT
else:
    FAILURE_LIMIT = 3

# see if the user has overridden the failure reset setting
if hasattr(settings, 'LOGIN_FAILURE_RESET'):
    FAILURE_RESET = settings.LOGIN_FAILURE_RESET
else:
    FAILURE_RESET = True

def query2str(items):
    return '\n'.join(['%s=%s' % (k, v) for k,v in items])

def watch_login(func, failures):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def new(*args, **kwargs):
        request = args[0]

        # call the login function
        response = func(*args, **kwargs)

        # only check when there's been an HTTP POST
        if request.method == 'POST':
            # see if the login was successful
            if not response.has_header('location') and response.status_code != 302:
                ip = request.META.get('REMOTE_ADDR', '')
                ua = request.META.get('HTTP_USER_AGENT', '<unknown>')

                key = '%s:%s' % (ip, ua)

                # make sure we have an item for this key
                try:
                    failures[key]
                except KeyError:
                    failures[key] = 0

                # add a failed attempt for this user
                failures[key] += 1

                # if we reach or surpass the failure limit, create an
                # AccessAttempt record
                if failures[key] >= FAILURE_LIMIT:
                    attempt = AccessAttempt.objects.create(
                        user_agent=ua,
                        ip_address=ip,
                        get_data=query2str(request.GET.items()),
                        post_data=query2str(request.POST.items()),
                        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
                        path_info=request.META.get('PATH_INFO', '<unknown>'),
                        failures_since_start=failures[key]
                    )

                    if FAILURE_RESET:
                        del(failures[key])

        return response
    return new