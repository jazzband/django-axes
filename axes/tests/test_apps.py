import warnings

from django.contrib.auth.views import LoginView
from django.test import TestCase

from axes.apps import patch_login_view


class PatchLoginViewTest(TestCase):
    def test_raises_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            patch_login_view()

        self.assertEqual(len(w), 1)
        self.assertEqual(w[0].category, DeprecationWarning)

    def test_patches_login_view_methods(self):
        original_dispatch = LoginView.dispatch
        original_form_invalid = LoginView.form_invalid

        patch_login_view()

        self.assertIsNot(LoginView.dispatch, original_dispatch)
        self.assertIsNot(LoginView.form_invalid, original_form_invalid)
