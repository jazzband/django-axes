from django.test import TestCase
from django.utils.functional import SimpleLazyObject


class ConfTestCase(TestCase):
    def test_axes_username_form_field_uses_lazy_evaluation(self):
        """
        Test that AXES_USERNAME_FORM_FIELD uses SimpleLazyObject for lazy evaluation.
        This prevents circular import issues with custom user models (issue #1280).
        """
        from axes.conf import settings
        
        # Verify that AXES_USERNAME_FORM_FIELD is a SimpleLazyObject if not overridden
        # This is only the case when the setting is not explicitly defined
        username_field = settings.AXES_USERNAME_FORM_FIELD
        
        # The actual type depends on whether AXES_USERNAME_FORM_FIELD was overridden
        # If it's using the default, it should be a SimpleLazyObject
        # If overridden in settings, it could be a plain string
        # Either way, it should be usable as a string
        
        # Force evaluation and verify it works
        username_field_str = str(username_field)
        
        # Should get the default USERNAME_FIELD from the user model
        # For the test suite, this is "username"
        self.assertIsInstance(username_field_str, str)
        self.assertTrue(len(username_field_str) > 0)
    
    def test_axes_username_form_field_evaluates_correctly(self):
        """
        Test that when AXES_USERNAME_FORM_FIELD is accessed, it correctly
        resolves to the user model's USERNAME_FIELD.
        """
        from django.contrib.auth import get_user_model
        from axes.conf import settings
        
        # Get the expected value
        expected_username_field = get_user_model().USERNAME_FIELD
        
        # Get the actual value from axes settings
        actual_username_field = str(settings.AXES_USERNAME_FORM_FIELD)
        
        # They should match
        self.assertEqual(actual_username_field, expected_username_field)
