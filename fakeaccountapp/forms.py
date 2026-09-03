from django import forms
from django.contrib.auth import get_user_model

from .validators import validate_username_uniqueness

User = get_user_model()


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput
    )

    class Meta:
        model = User
        fields = ["username", "password"]

    def clean_username(self):
        username = self.cleaned_data["username"]

        validate_username_uniqueness(username)

        return username