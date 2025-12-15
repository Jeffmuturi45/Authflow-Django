# accounts/utils.py - Updated with better error handling
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def send_otp_email(email, otp_code):
    """Send OTP email to user."""
    try:
        subject = 'Verify Your Account - AuthFlow'

        # Render HTML email
        html_message = render_to_string('emails/otp_email.html', {
            'otp_code': otp_code,
            'expiry_minutes': 1,
            'site_url': settings.SITE_URL
        })

        plain_message = strip_tags(html_message)

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"OTP email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {e}")
        # For development, print to console
        if settings.DEBUG:
            print(f"OTP for {email}: {otp_code}")
        return False


def send_password_reset_email(email, reset_token):
    """Send password reset email to user."""
    print(f"DEBUG: Starting send_password_reset_email for {email}")  # Debug
    print(f"DEBUG: Token: {reset_token}")  # Debug
    print(f"DEBUG: SITE_URL: {settings.SITE_URL}")  # Debug

    try:
        subject = 'Reset Your Password - AuthFlow'

        # Create reset link
        reset_link = f"{settings.SITE_URL}/accounts/reset-password/{reset_token}/"
        print(f"DEBUG: Reset link: {reset_link}")  # Debug

        # Check if template exists
        try:
            html_message = render_to_string('emails/password_reset.html', {
                'reset_link': reset_link,
                'expiry_hours': 1,
                'site_url': settings.SITE_URL
            })
            print(f"DEBUG: Email template rendered successfully")  # Debug
        except Exception as e:
            print(f"DEBUG: Failed to render template: {e}")  # Debug
            # Fallback simple email
            html_message = f"""
            <h2>Reset Your Password</h2>
            <p>Click here to reset your password: <a href="{reset_link}">{reset_link}</a></p>
            <p>This link expires in 1 hour.</p>
            """

        plain_message = strip_tags(html_message)

        print(f"DEBUG: Sending email with settings:")  # Debug
        print(f"  From: {settings.DEFAULT_FROM_EMAIL}")  # Debug
        print(f"  To: {email}")  # Debug
        print(f"  Subject: {subject}")  # Debug

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        print(f"DEBUG: Email sent successfully!")  # Debug
        logger.info(f"Password reset email sent to {email}")
        return True
    except Exception as e:
        # Debug
        print(f"DEBUG: Exception in send_password_reset_email: {str(e)}")
        logger.error(f"Failed to send password reset email to {email}: {e}")
        # For development, print to console
        if settings.DEBUG:
            print(f"Password reset link for {email}: {reset_link}")
        return False


def send_welcome_email(email, user):
    """Send welcome email to new user."""
    try:
        subject = 'Welcome to AuthFlow!'

        html_message = render_to_string('emails/welcome_email.html', {
            'user': user,
            'site_url': settings.SITE_URL
        })

        plain_message = strip_tags(html_message)

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"Welcome email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {e}")
        return False


def send_password_changed_email(email):
    """Send notification when password is changed."""
    try:
        subject = 'Password Changed - AuthFlow'

        html_message = render_to_string('emails/password_changed.html', {
            'site_url': settings.SITE_URL
        })

        plain_message = strip_tags(html_message)

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"Password changed notification sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password changed email to {email}: {e}")
        return False
