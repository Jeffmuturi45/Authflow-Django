# accounts/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

from .models import CustomUser, OTP, PasswordResetToken, LoginAttempt
from .forms import (
    RegistrationForm, LoginForm, OTPVerificationForm,
    ForgotPasswordForm, ResetPasswordForm, ProfileUpdateForm, ChangePasswordForm
)
from .utils import send_otp_email, send_password_reset_email, send_welcome_email, send_password_changed_email


# Custom handler for rate limited requests
def rate_limited_view(request, exception):
    """Handle rate limited requests."""
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({
            'success': False,
            'message': 'Too many requests. Please try again later.'
        }, status=429)

    messages.error(request, 'Too many requests. Please try again later.')
    return redirect('login')


# In accounts/views.py, ensure home_view is properly defined:

def home_view(request):
    """Home page view - redirects based on authentication status."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')

    return render(request, 'home.html')


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def register_view(request):
    """Handle user registration."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            # Create inactive user
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            # Check if user already exists (inactive users might exist)
            if CustomUser.objects.filter(email=email, is_active=False).exists():
                # Reactivate existing inactive user
                user = CustomUser.objects.get(email=email)
                user.set_password(password)
                user.save()
            else:
                # Create new user
                user = CustomUser.objects.create_user(
                    email=email,
                    password=password,
                    is_active=False  # User inactive until OTP verified
                )

            # Generate and send OTP
            otp_instance, otp_code = OTP.create_otp(
                user, purpose='email_verification')
            send_otp_email(email, otp_code)

            # Store email in session for OTP verification
            request.session['registration_email'] = email
            request.session['otp_created_at'] = timezone.now().isoformat()

            messages.success(
                request, 'Account created! Please check your email for the verification code.')
            return redirect('verify_otp')
        else:
            # Form has errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()

    return render(request, 'auth/register.html', {'form': form})


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    """Handle user login."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            remember = form.cleaned_data['remember']

            # Track login attempt
            login_attempt = LoginAttempt.objects.create(
                email=email,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False
            )

            # Authenticate user
            user = authenticate(request, email=email, password=password)

            if user is not None:
                # Check if user is active (verified)
                if not user.is_active:
                    messages.error(
                        request, 'Please verify your email before logging in.')
                    request.session['registration_email'] = email
                    return redirect('verify_otp')

                # Check if account is locked
                if user.is_locked:
                    if user.locked_until and user.locked_until > timezone.now():
                        messages.error(
                            request, 'Account is temporarily locked. Please try again later.')
                        login_attempt.save()
                        return render(request, 'auth/login.html', {'form': form})
                    else:
                        user.is_locked = False
                        user.locked_until = None
                        user.save()

                # Login user
                login(request, user)

                # Update login tracking
                user.last_login = timezone.now()
                user.last_login_ip = get_client_ip(request)
                user.login_count += 1
                user.save()

                # Update login attempt
                login_attempt.success = True
                login_attempt.save()

                # Set session expiry
                if not remember:
                    request.session.set_expiry(0)  # Browser session
                else:
                    request.session.set_expiry(1209600)  # 2 weeks

                messages.success(
                    request, f'Welcome back, {user.get_full_name() or user.email}!')
                return redirect('dashboard')
            else:
                # Failed login
                login_attempt.save()

                # Check if user exists but password is wrong
                if CustomUser.objects.filter(email=email).exists():
                    user = CustomUser.objects.get(email=email)
                    user.increment_otp_attempts()  # Track failed attempts

                    if user.is_locked:
                        messages.error(
                            request, 'Account is locked due to too many failed attempts. Please try again later.')
                    else:
                        messages.error(request, 'Invalid email or password.')
                else:
                    messages.error(request, 'Invalid email or password.')
        else:
            # Form has errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = LoginForm()

    return render(request, 'auth/login.html', {'form': form})


def verify_otp_view(request):
    """Handle OTP verification."""
    email = request.session.get('registration_email')

    if not email and not request.user.is_authenticated:
        messages.error(request, 'Please register or login first.')
        return redirect('register')

    if not email and request.user.is_authenticated:
        email = request.user.email

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp']
            email = form.cleaned_data['email']

            try:
                user = CustomUser.objects.get(email=email)

                # Get the latest OTP for this user
                otp_instance = OTP.objects.filter(
                    user=user,
                    purpose='email_verification',
                    is_used=False
                ).order_by('-created_at').first()

                if not otp_instance:
                    return JsonResponse({
                        'success': False,
                        'message': 'No OTP found. Please request a new one.'
                    })

                # Verify OTP
                if otp_instance.verify(otp_code):
                    # Activate user
                    user.is_active = True
                    user.email_verified = True
                    user.email_verified_at = timezone.now()
                    user.otp_attempts = 0  # Reset OTP attempts
                    user.save()

                    # Send welcome email
                    send_welcome_email(user.email, user)

                    # Log user in if not already logged in
                    if not request.user.is_authenticated:
                        login(request, user)

                    # Clear registration session
                    request.session.pop('registration_email', None)
                    request.session.pop('otp_created_at', None)

                    return JsonResponse({
                        'success': True,
                        'redirect_url': '/dashboard/'
                    })
                else:
                    if otp_instance.is_expired():
                        message = 'OTP has expired. Please request a new one.'
                    elif otp_instance.attempts >= 3:
                        message = 'Too many failed attempts. Please request a new OTP.'
                    else:
                        attempts_remaining = 3 - otp_instance.attempts
                        message = f'Invalid OTP. {attempts_remaining} attempts remaining.'

                    return JsonResponse({
                        'success': False,
                        'message': message,
                        'attempts_remaining': 3 - otp_instance.attempts
                    })

            except CustomUser.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'User not found.'
                })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid form data.'
            })

    # GET request - show OTP verification page
    form = OTPVerificationForm(initial={'email': email})
    return render(request, 'auth/verify_otp.html', {
        'form': form,
        'email': email
    })


@require_POST
@csrf_exempt
@ratelimit(key='ip', rate='3/m', method='POST', block=True)
def resend_otp_view(request):
    """Handle OTP resend request."""
    import json

    try:
        data = json.loads(request.body)
        email = data.get('email')

        if not email:
            return JsonResponse({
                'success': False,
                'message': 'Email is required.'
            })

        try:
            user = CustomUser.objects.get(email=email)

            # Check if user can request OTP (cooldown)
            if not user.can_request_otp():
                return JsonResponse({
                    'success': False,
                    'message': 'Please wait 30 seconds before requesting a new OTP.'
                })

            # Generate and send new OTP
            otp_instance, otp_code = OTP.create_otp(
                user, purpose='email_verification')
            send_otp_email(user.email, otp_code)

            # Update user's OTP timestamp
            user.otp_created_at = timezone.now()
            user.save()

            # Update session
            request.session['registration_email'] = email
            request.session['otp_created_at'] = timezone.now().isoformat()

            return JsonResponse({
                'success': True,
                'message': 'New OTP sent to your email.'
            })

        except CustomUser.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'User not found.'
            })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON data.'
        })

# In accounts/views.py, update forgot_password_view with debugging:


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def forgot_password_view(request):
    """Handle forgot password request."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            try:
                user = CustomUser.objects.get(email=email, is_active=True)
                # Debug line
                print(f"DEBUG: User found: {email}, active: {user.is_active}")

                # Create password reset token
                token_instance = PasswordResetToken.create_token(user)
                # Debug line
                print(f"DEBUG: Token created: {token_instance.token}")

                # Send password reset email
                try:
                    success = send_password_reset_email(
                        user.email, token_instance.token)
                    if success:
                        print(
                            f"DEBUG: Password reset email sent successfully to {user.email}")
                        messages.success(
                            request, 'Password reset link has been sent to your email.')
                    else:
                        print(
                            f"DEBUG: Failed to send password reset email to {user.email}")
                        messages.error(
                            request, 'Failed to send reset email. Please try again.')
                except Exception as e:
                    # Debug line
                    print(f"DEBUG: Exception sending email: {str(e)}")
                    messages.success(
                        request, 'If an account exists with this email, you will receive a reset link.')

                return render(request, 'auth/forgot_password.html', {
                    'form': form,
                    'email_sent': True
                })

            except CustomUser.DoesNotExist:
                # Debug line
                print(f"DEBUG: User not found or inactive: {email}")
                # Don't reveal that user doesn't exist (security best practice)
                messages.success(
                    request, 'If an account exists with this email, you will receive a reset link.')
                return render(request, 'auth/forgot_password.html', {
                    'form': form,
                    'email_sent': True
                })
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = ForgotPasswordForm()

    return render(request, 'auth/forgot_password.html', {'form': form})


def reset_password_view(request, token=None):
    """Handle password reset."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    # Validate token
    if token:
        try:
            token_instance = PasswordResetToken.objects.get(
                token=token, is_used=False)

            if token_instance.is_expired():
                messages.error(request, 'This reset link has expired.')
                return redirect('forgot_password')

            if request.method == 'POST':
                form = ResetPasswordForm(request.POST)
                if form.is_valid():
                    # Update password
                    user = token_instance.user
                    user.set_password(form.cleaned_data['new_password'])
                    user.save()

                    # Mark token as used
                    token_instance.is_used = True
                    token_instance.save()

                    # Send notification email
                    send_password_changed_email(user.email)

                    messages.success(
                        request, 'Password reset successful! You can now login with your new password.')
                    return redirect('login')
                else:
                    for field, errors in form.errors.items():
                        for error in errors:
                            messages.error(request, f"{field}: {error}")
            else:
                form = ResetPasswordForm()

            return render(request, 'auth/reset_password.html', {
                'form': form,
                'token': token,
                'email': token_instance.user.email
            })

        except PasswordResetToken.DoesNotExist:
            messages.error(request, 'Invalid reset link.')
            return redirect('forgot_password')

    # No token provided
    messages.error(request, 'Reset link is required.')
    return redirect('forgot_password')


@login_required
def dashboard_view(request):
    """Dashboard view for authenticated users."""
    user = request.user

    # Get user statistics
    login_count = user.login_count
    last_login = user.last_login
    joined_date = user.date_joined

    # Get recent OTPs (for display purposes)
    recent_otps = OTP.objects.filter(user=user).order_by('-created_at')[:5]

    return render(request, 'dashboard/dashboard.html', {
        'user': user,
        'login_count': login_count,
        'last_login': last_login,
        'joined_date': joined_date,
        'recent_otps': recent_otps,
    })


@login_required
def profile_view(request):
    """User profile view."""
    user = request.user

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            profile_form = ProfileUpdateForm(
                request.POST, request.FILES, instance=user)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, 'Profile updated successfully!')
                return redirect('profile')
            else:
                for field, errors in profile_form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
        elif 'change_password' in request.POST:
            password_form = ChangePasswordForm(user, request.POST)
            if password_form.is_valid():
                user.set_password(password_form.cleaned_data['new_password'])
                user.save()

                # Send password changed email
                send_password_changed_email(user.email)

                # Re-login user with new password
                login(request, user)

                messages.success(request, 'Password changed successfully!')
                return redirect('profile')
            else:
                for field, errors in password_form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
    else:
        profile_form = ProfileUpdateForm(instance=user)
        password_form = ChangePasswordForm(user)

    return render(request, 'dashboard/profile.html', {
        'user': user,
        'profile_form': profile_form,
        'password_form': password_form,
    })


@login_required
def logout_view(request):
    """Handle user logout."""
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip


# Placeholder views for URLs we haven't implemented yet
@login_required
def security_view(request):
    """Security settings view."""
    user = request.user

    # Get security statistics
    failed_logins = LoginAttempt.objects.filter(
        email=user.email, success=False).count()
    successful_logins = LoginAttempt.objects.filter(
        email=user.email, success=True).count()

    return render(request, 'dashboard/security.html', {
        'user': user,
        'failed_logins': failed_logins,
        'successful_logins': successful_logins,
    })


@login_required
def settings_view(request):
    """Account settings view."""
    user = request.user

    # Get account settings data
    email_notifications = True  # Default
    two_factor_enabled = False  # Default

    return render(request, 'dashboard/settings.html', {
        'user': user,
        'email_notifications': email_notifications,
        'two_factor_enabled': two_factor_enabled,
    })


@login_required
def delete_account_view(request):
    """Handle account deletion request."""
    if request.method == 'POST':
        user = request.user

        # Logout user
        logout(request)

        # Soft delete user (mark as inactive)
        user.is_active = False
        user.save()

        messages.success(
            request, 'Your account has been deleted successfully.')
        return redirect('login')

    return render(request, 'dashboard/delete_account.html')


@login_required
def export_data_view(request):
    """Export user data."""
    user = request.user

    # Get user data
    user_data = {
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'date_joined': user.date_joined.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'login_count': user.login_count,
        'email_verified': user.email_verified,
        'email_verified_at': user.email_verified_at.isoformat() if user.email_verified_at else None,
    }

    # Get login history
    login_history = list(LoginAttempt.objects.filter(email=user.email).values(
        'timestamp', 'ip_address', 'user_agent', 'success'
    ).order_by('-timestamp')[:100])

    data = {
        'user': user_data,
        'login_history': login_history,
    }

    # Return JSON response
    from django.http import JsonResponse
    return JsonResponse(data)


# In accounts/views.py, find the session_management_view function
# It should be around line 400-450

@login_required
def session_management_view(request):
    """Manage active sessions."""
    # Get all sessions for current user
    from django.contrib.sessions.models import Session

    user_sessions = []
    current_session_key = request.session.session_key

    # Simplified version - in production, you'd query actual sessions
    session_info = {
        'session_key': current_session_key,
        'expire_date': request.session.get_expiry_date(),
        'is_current': True,
    }
    user_sessions.append(session_info)

    if request.method == 'POST':
        messages.success(request, 'Session management is a premium feature.')
        return redirect('session_management')

    return render(request, 'dashboard/session_management.html', {
        'user_sessions': user_sessions,
    })


# Error handling views
def handler404(request, exception):
    """Custom 404 error handler."""
    return render(request, 'errors/404.html', status=404)


def handler500(request):
    """Custom 500 error handler."""
    return render(request, 'errors/500.html', status=500)


def handler403(request, exception):
    """Custom 403 error handler."""
    return render(request, 'errors/403.html', status=403)


def handler400(request, exception):
    """Custom 400 error handler."""
    return render(request, 'errors/400.html', status=400)


# API Views (for AJAX calls)
@require_POST
@csrf_exempt
@login_required
def check_email_availability(request):
    """Check if email is available for registration."""
    import json

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()

        if not email:
            return JsonResponse({
                'available': False,
                'message': 'Email is required.'
            })

        # Check if email exists and is active
        exists = CustomUser.objects.filter(
            email=email, is_active=True).exists()

        return JsonResponse({
            'available': not exists,
            'message': 'Email is already registered.' if exists else 'Email is available.'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'available': False,
            'message': 'Invalid request data.'
        })


@require_POST
@csrf_exempt
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def verify_password_strength(request):
    """Verify password strength."""
    import json
    import re

    try:
        data = json.loads(request.body)
        password = data.get('password', '')

        if not password:
            return JsonResponse({
                'valid': False,
                'score': 0,
                'message': 'Password is required.'
            })

        # Calculate password strength
        score = 0
        messages = []

        # Length check
        if len(password) >= 8:
            score += 1
        else:
            messages.append('At least 8 characters')

        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            messages.append('One uppercase letter')

        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            messages.append('One lowercase letter')

        # Number check
        if re.search(r'[0-9]', password):
            score += 1
        else:
            messages.append('One number')

        # Special character check
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            score += 1
        else:
            messages.append('One special character')

        # Determine strength level
        if score == 5:
            strength = 'Strong'
            color = 'green'
        elif score >= 3:
            strength = 'Good'
            color = 'blue'
        elif score >= 2:
            strength = 'Fair'
            color = 'yellow'
        else:
            strength = 'Weak'
            color = 'red'

        return JsonResponse({
            'valid': score >= 3,  # At least "Good" strength
            'score': score,
            'strength': strength,
            'color': color,
            'message': 'Password meets requirements.' if score >= 3 else f'Password needs: {", ".join(messages)}'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'valid': False,
            'score': 0,
            'message': 'Invalid request data.'
        })


# Activity logging middleware (for tracking user activity)
class ActivityLoggingMiddleware:
    """Middleware to log user activity."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Log activity for authenticated users
        if request.user.is_authenticated:
            from datetime import datetime

            # Log important actions
            if request.method in ['POST', 'PUT', 'DELETE']:
                # Get the view name
                view_name = ''
                if hasattr(request.resolver_match, 'view_name'):
                    view_name = request.resolver_match.view_name

                # Log sensitive actions
                sensitive_actions = [
                    'logout', 'change_password', 'delete_account']
                if any(action in view_name for action in sensitive_actions):
                    # Log the action (in a real app, save to database)
                    pass

        return response
