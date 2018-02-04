from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory
from django.utils.six.moves import http_client

from axes.views import AxesLoginView


class AxesLoginViewTest(TestCase):
    def setUp(self):
        self.rf = RequestFactory()
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='secret',
        )

    @patch('axes.views.is_already_locked', return_value=True)
    def test_dispatch(self, _):
        request = self.rf.post('/login/', {
            'username': 'test',
            'password': 'secret',
        })
        request.user = self.user

        view = AxesLoginView()
        view.request = request
        response = view.dispatch(request)

        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn('Account locked', response.content.decode('utf-8'))

    @patch('axes.views.is_already_locked', return_value=True)
    def test_form_invalid(self, _):
        request = self.rf.post('/login/', {
            'username': 'test',
            'password': 'secret',
        })
        request.user = self.user

        view = AxesLoginView()
        view.request = request
        response = view.form_invalid(Mock())

        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn('Account locked', response.content.decode('utf-8'))
