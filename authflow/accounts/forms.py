# accounts/forms.py
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import CustomUser
import re


class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        }),
        min_length=8
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password'
        })
    )

    class Meta:
        model = CustomUser
        fields = ('email', 'first_name', 'last_name')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")

        # Validate password strength
        if not re.search(r'[A-Z]', password1):
            raise ValidationError(
                "Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password1):
            raise ValidationError(
                "Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', password1):
            raise ValidationError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password1):
            raise ValidationError(
                "Password must contain at least one special character")

        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = CustomUser
        fields = ('email', 'password', 'first_name', 'last_name',
                  'is_active', 'is_staff', 'is_superuser')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]


class RegistrationForm(forms.Form):
    """Form for user registration."""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'you@example.com'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': '••••••••'
        }),
        min_length=8
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': '••••••••'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords don't match")

        # Validate password strength
        if password:
            if not re.search(r'[A-Z]', password):
                self.add_error(
                    'password', "Password must contain at least one uppercase letter")
            if not re.search(r'[a-z]', password):
                self.add_error(
                    'password', "Password must contain at least one lowercase letter")
            if not re.search(r'[0-9]', password):
                self.add_error(
                    'password', "Password must contain at least one number")
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
                self.add_error(
                    'password', "Password must contain at least one special character")

        return cleaned_data

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email


class LoginForm(forms.Form):
    """Form for user login."""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'you@example.com'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': '••••••••'
        })
    )
    remember = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded'
        })
    )


class OTPVerificationForm(forms.Form):
    """Form for OTP verification."""
    otp = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'hidden',  # Hidden, handled by JavaScript
        })
    )
    email = forms.EmailField(
        widget=forms.HiddenInput()
    )


class ForgotPasswordForm(forms.Form):
    """Form for password reset request."""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'you@example.com'
        })
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not CustomUser.objects.filter(email=email, is_active=True).exists():
            raise ValidationError("No account found with this email address.")
        return email


class ResetPasswordForm(forms.Form):
    """Form for resetting password."""
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': '••••••••'
        }),
        min_length=8
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 pl-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': '••••••••'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password and new_password != confirm_password:
            self.add_error('confirm_password', "Passwords don't match")

        # Validate password strength
        if new_password:
            if not re.search(r'[A-Z]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one uppercase letter")
            if not re.search(r'[a-z]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one lowercase letter")
            if not re.search(r'[0-9]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one number")
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one special character")

        return cleaned_data


class ProfileUpdateForm(forms.ModelForm):
    """Form for updating user profile."""
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'phone_number', 'avatar']
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                'placeholder': 'First Name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                'placeholder': 'Last Name'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                'placeholder': 'Phone Number'
            }),
            'avatar': forms.FileInput(attrs={
                'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent'
            }),
        }


class ChangePasswordForm(forms.Form):
    """Form for changing password."""
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'Current Password'
        })
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'New Password'
        }),
        min_length=8
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent',
            'placeholder': 'Confirm New Password'
        })
    )

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        current_password = cleaned_data.get('current_password')
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        # Check current password
        if self.user and not self.user.check_password(current_password):
            self.add_error('current_password', "Current password is incorrect")

        # Check if new passwords match
        if new_password and confirm_password and new_password != confirm_password:
            self.add_error('confirm_password', "New passwords don't match")

        # Check if new password is same as current
        if current_password and new_password and current_password == new_password:
            self.add_error(
                'new_password', "New password must be different from current password")

        # Validate password strength
        if new_password:
            if not re.search(r'[A-Z]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one uppercase letter")
            if not re.search(r'[a-z]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one lowercase letter")
            if not re.search(r'[0-9]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one number")
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', new_password):
                self.add_error(
                    'new_password', "Password must contain at least one special character")

        return cleaned_data
