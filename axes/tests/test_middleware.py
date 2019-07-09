from django.http import HttpResponse, HttpRequest

from axes.middleware import AxesMiddleware
from axes.tests.base import AxesTestCase


class MiddlewareTestCase(AxesTestCase):
    STATUS_SUCCESS = 200
    STATUS_LOCKOUT = 403

    def setUp(self):
        self.request = HttpRequest()

    def test_success_response(self):
        def get_response(request):
            request.axes_locked_out = False
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_SUCCESS)

    def test_lockout_response(self):
        def get_response(request):
            request.axes_locked_out = True
            return HttpResponse()

        response = AxesMiddleware(get_response)(self.request)
        self.assertEqual(response.status_code, self.STATUS_LOCKOUT)
