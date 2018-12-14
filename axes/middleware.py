from django.urls import resolve


class M3Middleware(object):
    """Middleware that adds 'M3' header to request
    providing support for M3 platform.

    So AXES knows that it needs to use special
    OperationResult response.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        # We exclude standard django admin urls, since
        # they don't require OperationResult response.
        # Will need to override this middleware if
        # more urls need to be excluded.

        namespace = resolve(request.path_info).namespace
        if not namespace == 'admin':
            request.META['AXES_USERNAME_FORM_FIELD'] = 'login_login'
            request.META['AXES_PLATFORM'] = 'M3'
        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response