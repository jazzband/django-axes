from utils import VERBOSE
from utils import log
from utils import is_already_locked
from utils import lockout_response
from utils import create_access_log
from utils import check_request
from utils import is_login_unsuccessful

def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login' and VERBOSE:
            log.info('AXES: Calling decorated function: %s' % func.__name__)
            if args:
                log.info('args: %s' % str(args))
            if kwargs:
                log.info('kwargs: %s' % kwargs)

        # TODO: create a class to hold the attempts records and perform checks
        # with its methods? or just store attempts=get_user_attempts here and
        # pass it to the functions
        # also no need to keep accessing these:
        # ip = request.META.get('REMOTE_ADDR', '')
        # ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        # username = request.POST.get('username', None)

        # if the request is currently under lockout, do not proceed to the
        # login function, go directly to lockout url, do not pass go, do not
        # collect messages about this login attempt
        if is_already_locked(request):
            return lockout_response(request, populate_login_form=True)

        # call the login function
        response = func(request, *args, **kwargs)

        if func.__name__ == 'decorated_login':
            # if we're dealing with this function itself, don't bother checking
            # for invalid login attempts.  I suppose there's a bunch of
            # recursion going on here that used to cause one failed login
            # attempt to generate 10+ failed access attempt records (with 3
            # failed attempts each supposedly)
            return response

        if request.method == 'POST':
            # see if the login was successful
            login_unsuccessful = is_login_unsuccessful(response)

            # create a log of a login attempt
            create_access_log(request, login_unsuccessful)

            if check_request(request, login_unsuccessful):
                return response

            return lockout_response(request, populate_login_form=True)

        return response

    return decorated_login
