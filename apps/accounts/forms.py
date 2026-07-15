"""
Account forms for user registration and authentication.

Provides styled form classes that integrate with the platform's UI design,
using consistent CSS class names and placeholder text for all input fields.
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User


class RegisterForm(UserCreationForm):
    """
    Extended user registration form with required email field.
    
    Inherits from Django's UserCreationForm and adds an email field.
    All fields are styled with 'form-input' CSS class and descriptive
    placeholder text for a polished UI experience.
    """

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                'class': 'form-input',
                'placeholder': 'Email address',
            }
        ),
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'form-input',
                'placeholder': field.label,
            })

    def save(self, commit=True):
        """Save the user with the provided email address."""
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    """
    Styled authentication form.
    
    Extends Django's built-in AuthenticationForm with consistent
    'form-input' CSS class and placeholder attributes on all fields.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'form-input',
                'placeholder': field.label,
            })
