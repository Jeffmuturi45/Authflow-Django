# accounts/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from .models import CustomUser, OTP
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=CustomUser)
def send_welcome_email_on_verification(sender, instance, created, **kwargs):
    """
    Send welcome email when user is verified (email_verified becomes True).
    """
    if not created and instance.email_verified:
        # Check if email was just verified
        try:
            # Get previous state
            previous = CustomUser.objects.get(pk=instance.pk)
            if not previous.email_verified:
                # Email was just verified, send welcome email
                subject = 'Welcome to AuthFlow!'

                html_message = render_to_string('emails/welcome_email.html', {
                    'user': instance
                })

                plain_message = strip_tags(html_message)

                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[instance.email],
                    html_message=html_message,
                    fail_silently=True,
                )

                logger.info(f"Welcome email sent to {instance.email}")
        except CustomUser.DoesNotExist:
            pass


@receiver(post_save, sender=CustomUser)
def handle_user_creation(sender, instance, created, **kwargs):
    """
    Handle actions when a new user is created.
    """
    if created:
        # Log user creation
        logger.info(f"New user created: {instance.email}")

        # You can add additional initialization logic here
        # For example, create user profile, send admin notification, etc.


@receiver(post_save, sender=OTP)
def log_otp_creation(sender, instance, created, **kwargs):
    """
    Log when an OTP is created.
    """
    if created:
        logger.info(
            f"OTP created for {instance.user.email} - Purpose: {instance.purpose}")
