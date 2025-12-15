# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.mail import send_mail
import secrets
from django.utils.crypto import get_random_string
import hashlib
import time


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name='email address')
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)

    # User status fields
    # Not active until OTP verified
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    # Profile fields
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True)

    # Email verification
    email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    # Security fields
    otp_secret = models.CharField(max_length=100, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    otp_attempts = models.IntegerField(default=0)
    otp_last_attempt = models.DateTimeField(null=True, blank=True)

    # Account lock
    is_locked = models.BooleanField(default=False)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Login tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.IntegerField(default=0)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def __str__(self):
        return self.email

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = f'{self.first_name} {self.last_name}'
        return full_name.strip()

    def get_short_name(self):
        """
        Return the short name for the user.
        """
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Send an email to this user.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def is_verified(self):
        """
        Check if the user's email is verified.
        """
        return self.email_verified

    def can_request_otp(self):
        """
        Check if user can request a new OTP (cooldown period).
        """
        if not self.otp_created_at:
            return True

        cooldown_period = timezone.now() - self.otp_created_at
        return cooldown_period.total_seconds() > 30  # 30 seconds cooldown

    def increment_otp_attempts(self):
        """
        Increment OTP attempt counter.
        """
        self.otp_attempts += 1
        self.otp_last_attempt = timezone.now()

        # Lock account if too many attempts
        if self.otp_attempts >= 3:
            self.is_locked = True
            self.locked_until = timezone.now() + timezone.timedelta(minutes=10)

        self.save()


class OTP(models.Model):
    """
    Model to store OTPs for email verification.
    """
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='otps')
    otp_hash = models.CharField(max_length=256)  # Store hashed OTP
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)

    # Purpose of OTP
    PURPOSE_CHOICES = [
        ('email_verification', 'Email Verification'),
        ('password_reset', 'Password Reset'),
        ('login_verification', 'Login Verification'),
    ]
    purpose = models.CharField(
        max_length=20, choices=PURPOSE_CHOICES, default='email_verification')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_used', 'expires_at']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"OTP for {self.user.email} - {self.purpose}"

    def is_expired(self):
        """
        Check if OTP has expired.
        """
        return timezone.now() > self.expires_at

    def is_valid(self):
        """
        Check if OTP is valid (not used and not expired).
        """
        return not self.is_used and not self.is_expired() and self.attempts < 3

    def verify(self, otp_input):
        """
        Verify the OTP input against stored hash.
        """
        if not self.is_valid():
            return False

        # Hash the input and compare
        otp_hash = self._hash_otp(otp_input)
        if otp_hash == self.otp_hash:
            self.is_used = True
            self.save()
            return True

        # Increment attempts on failure
        self.attempts += 1
        self.save()
        return False

    def _hash_otp(self, otp):
        """
        Hash the OTP for secure storage.
        """
        salt = "authflow_salt"  # In production, use a secure random salt
        return hashlib.sha256(f"{otp}{salt}{self.user.id}".encode()).hexdigest()

    @classmethod
    def create_otp(cls, user, purpose='email_verification'):
        """
        Create a new OTP for a user.
        """
        # Generate 6-digit OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')

        # Create OTP instance with hashed value
        otp_instance = cls.objects.create(
            user=user,
            purpose=purpose,
            expires_at=timezone.now() + timezone.timedelta(minutes=1)  # 1 minute expiry
        )

        # Store hashed OTP
        otp_instance.otp_hash = otp_instance._hash_otp(otp)
        otp_instance.save()

        return otp_instance, otp


# In accounts/models.py, update PasswordResetToken.create_token method:

@classmethod
def create_token(cls, user):
    """
    Create a new password reset token.
    """
    import secrets
    from django.utils import timezone

    # Generate secure token
    token = secrets.token_urlsafe(50)
    print(f"DEBUG: Generated token: {token}")  # Debug line

    # Create token instance
    token_instance = cls.objects.create(
        user=user,
        token=token,
        expires_at=timezone.now() + timezone.timedelta(hours=1)  # 1 hour expiry
    )
    print(f"DEBUG: Token instance created: {token_instance.id}")  # Debug line

    return token_instance


class PasswordResetToken(models.Model):
    """
    Model to store password reset tokens.
    """
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token', 'is_used', 'expires_at']),
        ]

    def __str__(self):
        return f"Reset token for {self.user.email}"

    def is_expired(self):
        """
        Check if token has expired.
        """
        return timezone.now() > self.expires_at

    def is_valid(self):
        """
        Check if token is valid (not used and not expired).
        """
        return not self.is_used and not self.is_expired()

    @classmethod
    def create_token(cls, user):
        """
        Create a new password reset token.
        """
        # Generate secure token
        token = secrets.token_urlsafe(50)

        # Create token instance
        token_instance = cls.objects.create(
            user=user,
            token=token,
            expires_at=timezone.now() + timezone.timedelta(hours=1)  # 1 hour expiry
        )

        return token_instance


class LoginAttempt(models.Model):
    """
    Model to track login attempts for rate limiting.
    """
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['email', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"Login attempt for {self.email} - {'Success' if self.success else 'Failed'}"
