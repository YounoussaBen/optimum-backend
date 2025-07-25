import secrets
import uuid
from datetime import timedelta

# from django.conf import settings  # Will be used for future settings-based configuration
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

    # Address Information
    address = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="User's street address (optional)",
    )

    city = models.CharField(
        max_length=100, blank=True, null=True, help_text="User's city (optional)"
    )

    postal_code = models.CharField(
        max_length=20, blank=True, null=True, help_text="User's postal code (optional)"
    )

    country = models.CharField(
        max_length=100, blank=True, null=True, help_text="User's country (optional)"
    )

    GENDER_CHOICES = [
        ("M", "Male"),
        ("F", "Female"),
        ("O", "Other"),
        ("P", "Prefer not to say"),
    ]

    gender = models.CharField(
        max_length=1, choices=GENDER_CHOICES, help_text="User's gender"
    )

    profile_picture = models.URLField(
        blank=True,
        null=True,
        max_length=500,
        help_text="URL to user's profile picture stored in Azure Blob Storage",
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

    auth_faces_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of faces added during successful authentications (max 100)",
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
        """Check if user can authenticate (active, face registered)."""
        return self.is_active and self.is_face_registered

    @property
    def can_add_more_auth_faces(self):
        """Check if user can have more faces added during authentication."""
        return self.auth_faces_count < 100

    @property
    def is_verification_expired(self):
        """
        Check if face verification has expired.

        Verification expires 30 days after being set to true.
        If verification_expires_at is None and user is verified, treat as expired.
        """
        if not self.is_verified:
            return False  # Can't expire if not verified

        if not self.verification_expires_at:
            # Users without expiration date are treated as expired
            return True

        return timezone.now() > self.verification_expires_at

    def expire_verification(self):
        """Manually expire user's verification."""
        self.is_verified = False
        self.verification_expires_at = None
        self.save(update_fields=["is_verified", "verification_expires_at"])

    def set_verified_with_expiration(self, verified_by_admin=False):
        """
        Set user as verified with 30-day expiration timer.

        Args:
            verified_by_admin (bool): Whether this was set by admin or user (for logging purposes)
        """
        self.is_verified = True

        # Set expiration time to 30 days from now
        # Note: verified_by_admin parameter is preserved for API compatibility
        self.verification_expires_at = timezone.now() + timedelta(days=30)

        self.save(update_fields=["is_verified", "verification_expires_at"])

        return self.verification_expires_at

    def increment_auth_faces_count(self):
        """Increment the count of authentication-based faces."""
        if self.can_add_more_auth_faces:
            self.auth_faces_count += 1
            self.save(update_fields=["auth_faces_count"])
            return True
        return False


class OTP(models.Model):
    """
    One Time Password model for SMS/Email authentication.

    OTPs are used for user authentication via SMS or email.
    Each OTP expires after 60 seconds for security.
    """

    DELIVERY_METHODS = [
        ("sms", "SMS"),
        ("email", "Email"),
    ]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the OTP",
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="otps",
        help_text="User this OTP belongs to",
    )

    code = models.CharField(max_length=6, help_text="6-digit OTP code")

    delivery_method = models.CharField(
        max_length=5,
        choices=DELIVERY_METHODS,
        help_text="Method used to deliver the OTP (SMS or Email)",
    )

    is_used = models.BooleanField(
        default=False, help_text="Whether this OTP has been used for authentication"
    )

    is_expired = models.BooleanField(
        default=False, help_text="Whether this OTP has expired"
    )

    created_at = models.DateTimeField(
        default=timezone.now, help_text="When the OTP was created"
    )

    expires_at = models.DateTimeField(help_text="When the OTP expires")

    used_at = models.DateTimeField(
        null=True, blank=True, help_text="When the OTP was used"
    )

    class Meta:
        db_table = "users_otp"
        verbose_name = "OTP"
        verbose_name_plural = "OTPs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "code"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["expires_at"]),
        ]

    def save(self, *args, **kwargs):
        """Override save to set expiration time and generate code."""
        if not self.code:
            self.code = self._generate_otp_code()

        if not self.expires_at:
            # OTP expires after 60 seconds
            self.expires_at = timezone.now() + timedelta(seconds=60)

        super().save(*args, **kwargs)

    def _generate_otp_code(self):
        """Generate a secure 6-digit OTP code."""
        return "".join([str(secrets.randbelow(10)) for _ in range(6)])

    def __str__(self):
        return f"OTP for {self.user.email} via {self.delivery_method} - {self.code}"

    @property
    def is_valid(self):
        """Check if OTP is valid (not used, not expired, and within time limit)."""
        if self.is_used or self.is_expired:
            return False

        # Check if expired by time
        if timezone.now() > self.expires_at:
            self.is_expired = True
            self.save(update_fields=["is_expired"])
            return False

        return True

    def mark_as_used(self):
        """Mark OTP as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=["is_used", "used_at"])

    def get_masked_contact(self):
        """Return masked contact information for display."""
        if self.delivery_method == "email":
            email = self.user.email
            local, domain = email.split("@")
            if len(local) <= 3:
                masked_local = local[0] + "*" * (len(local) - 1)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"

        elif self.delivery_method == "sms":
            phone = self.user.phone_number
            # Remove any non-digit characters for processing
            digits_only = "".join(filter(str.isdigit, phone))

            if len(digits_only) >= 7:
                # Show first 3 and last 2 digits, mask the middle
                visible_start = digits_only[:3]
                visible_end = digits_only[-2:]
                masked_middle = "*" * (len(digits_only) - 5)
                masked_digits = visible_start + masked_middle + visible_end

                # Preserve the original format structure
                if phone.startswith("+"):
                    return f"+{masked_digits[:3]} {masked_digits[3:5]} {masked_digits[5:7]} **{masked_digits[-2:]}"
                else:
                    return masked_digits
            else:
                # For shorter numbers, just mask most digits
                return phone[:-2] + "**"

        return "***"
