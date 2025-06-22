import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.validators import MinLengthValidator, RegexValidator
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model for financial application users.

    This model is designed for users who authenticate via face recognition + PIN,
    not traditional passwords. Only admin users use Django's built-in User model.
    """

    # Use UUID as primary key for better security and scalability
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the user",
    )

    # Core Identity Fields
    email = models.EmailField(
        unique=True, max_length=254, help_text="User's email address - must be unique"
    )

    first_name = models.CharField(
        max_length=50, validators=[MinLengthValidator(2)], help_text="User's first name"
    )

    middle_name = models.CharField(
        max_length=50, blank=True, help_text="User's middle name (optional)"
    )

    last_name = models.CharField(
        max_length=50, validators=[MinLengthValidator(2)], help_text="User's last name"
    )

    # Contact Information
    phone_number = models.CharField(
        max_length=20,
        unique=True,
        validators=[
            RegexValidator(
                regex=r"^\+?[1-9]\d{1,14}$",
                message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.",
            )
        ],
        help_text="User's phone number in international format",
    )

    # Personal Information
    date_of_birth = models.DateField(
        help_text="User's date of birth",
        null=True,
        blank=True,
    )

    nationality = models.CharField(max_length=50, help_text="User's nationality")

    GENDER_CHOICES = [
        ("M", "Male"),
        ("F", "Female"),
        ("O", "Other"),
        ("P", "Prefer not to say"),
    ]

    gender = models.CharField(
        max_length=1, choices=GENDER_CHOICES, help_text="User's gender"
    )

    # Authentication Fields
    unique_pin_identifier = models.CharField(
        max_length=9,
        unique=True,
        editable=False,  # Auto-generated, not user-editable
        help_text="9-digit PIN for user identification and authentication",
    )

    # Azure Face API Integration
    person_id = models.CharField(
        max_length=100,
        blank=True,
        help_text="Azure Face API Person ID from Person Group",
    )

    face_added = models.BooleanField(
        default=False, help_text="Whether user has completed face registration"
    )

    # User Status
    is_active = models.BooleanField(
        default=True,
        help_text="Designates whether this user should be treated as active",
    )

    is_verified = models.BooleanField(
        default=False, help_text="Whether user has been verified by admin"
    )

    verification_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When face verification expires and user needs to re-verify",
    )

    is_staff = models.BooleanField(
        default=False, help_text="Designates whether the user can access the admin site"
    )

    # External API Data Storage
    external_data = models.JSONField(
        blank=True, null=True, help_text="Store external API responses and metadata"
    )

    # Metadata
    date_joined = models.DateTimeField(
        default=timezone.now, help_text="When the user account was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text="When the user account was last updated"
    )

    # Manager
    objects = UserManager()

    # Django Auth Configuration
    USERNAME_FIELD = "email"  # Use email as the unique identifier
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "users_user"
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ["-date_joined"]
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["phone_number"]),
            models.Index(fields=["unique_pin_identifier"]),
            models.Index(fields=["person_id"]),
        ]

    def __str__(self):
        return f"{self.get_full_name()} ({self.email})"

    def get_full_name(self):
        """Return the user's full name."""
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}".strip()
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        """Return the user's short name."""
        return self.first_name

    def save(self, *args, **kwargs):
        """Override save to auto-generate PIN if not provided."""
        if not self.unique_pin_identifier:
            self.unique_pin_identifier = self._generate_unique_pin()
        super().save(*args, **kwargs)

    def _generate_unique_pin(self):
        """Generate a unique 8-digit PIN."""
        while True:
            # Generate random 8-digit number
            pin = get_random_string(8, allowed_chars="0123456789")
            # Ensure it doesn't already exist
            if not User.objects.filter(unique_pin_identifier=pin).exists():
                return pin

    @property
    def is_face_registered(self):
        """Check if user has completed face registration."""
        return self.face_added and bool(self.person_id)

    @property
    def can_authenticate(self):
        """Check if user can authenticate (active, verified, face registered)."""
        return self.is_active and self.is_verified and self.is_face_registered

    @property
    def is_verification_expired(self):
        """
        Check if face verification has expired.

        NEW LOGIC:
        - If verification_expires_at is None AND user is verified:
          Treat as expired (force monthly verification)
        - If verification_expires_at is set: Check actual expiration time
        - If user is not verified: Not applicable
        """
        if not self.is_verified:
            return False  # Can't expire if not verified

        if not self.verification_expires_at:
            # Admin-verified users without expiration are treated as expired
            # This forces them to do monthly self-verification
            return True

        return timezone.now() > self.verification_expires_at

    def expire_verification(self):
        """Manually expire user's verification."""
        self.is_verified = False
        self.verification_expires_at = None
        self.save(update_fields=["is_verified", "verification_expires_at"])

    def set_verified_with_expiration(self, verified_by_admin=False):
        """
        Set user as verified with proper expiration timer.

        Args:
            verified_by_admin (bool): Whether this was set by admin or user
        """
        self.is_verified = True

        # Get verification duration from settings
        verification_duration = settings.FACE_VERIFICATION_DURATION_MINUTES

        # Set expiration time for ALL verifications (admin or user)
        self.verification_expires_at = timezone.now() + timedelta(
            minutes=verification_duration
        )

        self.save(update_fields=["is_verified", "verification_expires_at"])

        return self.verification_expires_at
