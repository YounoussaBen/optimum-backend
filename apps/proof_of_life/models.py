import uuid
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

User = get_user_model()


class ProofOfLifePendingVerification(models.Model):
    """
    Temporary model to track proof of life verification in progress.

    This model stores face recognition results before OTP verification.
    Records are deleted after successful OTP verification or expiration.
    """

    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the pending verification",
    )

    # Foreign key to user
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="proof_of_life_pending_verifications",
        help_text="User who is performing the verification",
    )

    # Face recognition results
    confidence_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="confidence score (0.000 to 1.000)",
    )

    liveness_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="liveness score (0.000 to 1.000)",
    )

    # Device information
    device_id = models.CharField(
        max_length=255, help_text="Device identifier from the app"
    )

    device_platform = models.CharField(
        max_length=20,
        choices=[
            ("android", "Android"),
            ("ios", "iOS"),
            ("web", "Web"),
        ],
        help_text="Platform the verification was performed on",
    )

    app_version = models.CharField(
        max_length=50, help_text="App version used for verification"
    )

    os_version = models.CharField(max_length=50, help_text="Operating system version")

    # Verification session details
    session_token = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique session token for this verification attempt",
    )

    face_verification_timestamp = models.DateTimeField(
        help_text="When the face verification was completed"
    )

    # Expiration and status
    expires_at = models.DateTimeField(
        help_text="When this pending verification expires (10 minutes)"
    )

    is_otp_sent = models.BooleanField(
        default=False, help_text="Whether OTP has been sent for this verification"
    )

    otp_method = models.CharField(
        max_length=10,
        choices=[
            ("email", "Email"),
            ("sms", "SMS"),
        ],
        null=True,
        blank=True,
        help_text="Method used to send OTP",
    )

    # Audit fields
    created_at = models.DateTimeField(
        default=timezone.now, help_text="When this pending verification was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text="When this pending verification was last updated"
    )

    class Meta:
        db_table = "proof_of_life_pending_verifications"
        verbose_name = "Proof of Life Pending Verification"
        verbose_name_plural = "Proof of Life Pending Verifications"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["session_token"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"Pending Verification - {self.user.get_full_name()} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    def save(self, *args, **kwargs):
        """Override save to set session_token and expires_at if not provided."""
        if not self.session_token:
            self.session_token = self._generate_session_token()

        if not self.expires_at:
            # Pending verifications expire after 10 minutes
            self.expires_at = self.face_verification_timestamp + timedelta(minutes=10)

        super().save(*args, **kwargs)

    def _generate_session_token(self):
        """Generate a unique session token."""
        timestamp = (
            int(self.face_verification_timestamp.timestamp())
            if self.face_verification_timestamp
            else int(timezone.now().timestamp())
        )
        return f"polvf_{self.user.id.hex[:8]}_{timestamp}"

    @property
    def is_expired(self):
        """Check if this pending verification has expired."""
        return timezone.now() > self.expires_at

    @property
    def is_face_verification_successful(self):
        """Check if face verification meets minimum requirements."""
        from .models import ProofOfLifeSettings

        settings = ProofOfLifeSettings.get_settings()
        return (
            self.confidence_score >= settings.minimum_confidence_score
            and self.liveness_score >= settings.minimum_liveness_score
        )

    def mark_otp_sent(self, method):
        """Mark that OTP has been sent for this verification."""
        self.is_otp_sent = True
        self.otp_method = method
        self.save(update_fields=["is_otp_sent", "otp_method", "updated_at"])

    def convert_to_full_verification(self):
        """Convert this pending verification to a full ProofOfLifeVerification."""
        if not self.is_face_verification_successful:
            raise ValueError(
                "Face verification scores do not meet minimum requirements"
            )

        if self.is_expired:
            raise ValueError("Pending verification has expired")

        # Create the full verification record
        verification = ProofOfLifeVerification.objects.create(
            user=self.user,
            confidence_score=self.confidence_score,
            liveness_score=self.liveness_score,
            verification_date=timezone.now(),  # Use current time as final verification time
            device_id=self.device_id,
            device_platform=self.device_platform,
            app_version=self.app_version,
            os_version=self.os_version,
            status="current",
        )

        # Delete this pending verification
        self.delete()

        return verification


class ProofOfLifeVerification(models.Model):
    """
    Proof of Life Verification model for tracking monthly user verifications.

    This model stores verification records when users complete their monthly
    proof of life verification using face recognition + OTP verification.
    """

    STATUS_CHOICES = [
        ("current", "Current"),
        ("due_soon", "Due Soon"),
        ("overdue", "Overdue"),
        ("blocked", "Blocked"),
    ]

    PLATFORM_CHOICES = [
        ("android", "Android"),
        ("ios", "iOS"),
        ("web", "Web"),
    ]

    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the verification record",
    )

    # Foreign key to user
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="proof_of_life_verifications",
        help_text="User who performed the verification",
    )

    # Verification details
    verification_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique identifier for this verification session",
    )

    confidence_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="confidence score (0.000 to 1.000)",
    )

    liveness_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="liveness score (0.000 to 1.000)",
    )

    # Timestamps
    verification_date = models.DateTimeField(
        help_text="When the verification was performed"
    )

    next_due_date = models.DateTimeField(
        help_text="When the next verification is due (30 days from verification)"
    )

    # Device information for security audit
    device_id = models.CharField(
        max_length=255, help_text="Device identifier from the app"
    )

    device_platform = models.CharField(
        max_length=20,
        choices=PLATFORM_CHOICES,
        help_text="Platform the verification was performed on",
    )

    app_version = models.CharField(
        max_length=50, help_text="App version used for verification"
    )

    os_version = models.CharField(max_length=50, help_text="Operating system version")

    # Status and metadata
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="current",
        help_text="Current status of the verification",
    )

    # Audit fields
    created_at = models.DateTimeField(
        default=timezone.now, help_text="When this record was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text="When this record was last updated"
    )

    class Meta:
        db_table = "proof_of_life_verifications"
        verbose_name = "Proof of Life Verification"
        verbose_name_plural = "Proof of Life Verifications"
        ordering = ["-verification_date"]
        indexes = [
            models.Index(fields=["user", "verification_date"]),
            models.Index(fields=["user", "status"]),
            models.Index(fields=["next_due_date"]),
            models.Index(fields=["verification_date"]),
            models.Index(fields=["status"]),
            models.Index(fields=["verification_id"]),
        ]

    def __str__(self):
        return f"Proof of Life - {self.user.get_full_name()} - {self.verification_date.strftime('%Y-%m-%d')}"

    def save(self, *args, **kwargs):
        """Override save to set verification_id and next_due_date if not provided."""
        if not self.verification_id:
            self.verification_id = self._generate_verification_id()

        if not self.next_due_date:
            # Set next due date to 30 days from verification date
            self.next_due_date = self.verification_date + timedelta(days=30)

        super().save(*args, **kwargs)

    def _generate_verification_id(self):
        """Generate a unique verification ID."""
        timestamp = (
            int(self.verification_date.timestamp())
            if self.verification_date
            else int(timezone.now().timestamp())
        )
        return f"pol_{self.user.id.hex[:8]}_{timestamp}"

    @property
    def is_verification_successful(self):
        """Check if verification meets minimum requirements."""
        return self.confidence_score >= Decimal(
            "0.85"
        ) and self.liveness_score >= Decimal("0.80")

    @property
    def days_until_due(self):
        """Calculate days until next verification is due."""
        if not self.next_due_date:
            return 0
        delta = self.next_due_date.date() - timezone.now().date()
        return delta.days

    @property
    def is_overdue(self):
        """Check if verification is overdue."""
        return self.days_until_due < 0

    @property
    def urgency_level(self):
        """Get urgency level for notifications (0-3)."""
        days = self.days_until_due
        if days > 5:
            return 0  # No urgency
        elif days >= 1:
            return 1  # Due soon
        elif days >= -3:
            return 2  # Overdue
        else:
            return 3  # Critical

    def update_status(self):
        """Update status based on current date and next due date."""
        days = self.days_until_due

        if days > 5:
            self.status = "current"
        elif days >= 1:
            self.status = "due_soon"
        elif days >= -3:
            self.status = "overdue"
        else:
            self.status = "blocked"

        self.save(update_fields=["status", "updated_at"])
        return self.status


class ProofOfLifeSettings(models.Model):
    """
    Global settings for proof of life verification system.

    This model stores configurable settings like minimum scores,
    verification intervals, and grace periods.
    """

    # Singleton pattern - only one settings record should exist
    id = models.AutoField(primary_key=True)

    # Minimum score requirements
    minimum_confidence_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal("0.85"),
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="Minimum confidence score required for successful verification",
    )

    minimum_liveness_score = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal("0.80"),
        validators=[
            MinValueValidator(Decimal("0.000")),
            MaxValueValidator(Decimal("1.000")),
        ],
        help_text="Minimum liveness score required for successful verification",
    )

    # Timing settings
    verification_interval_days = models.PositiveIntegerField(
        default=30, help_text="Number of days between required verifications"
    )

    grace_period_days = models.PositiveIntegerField(
        default=3, help_text="Number of days after due date before blocking actions"
    )

    # Notification settings
    first_reminder_days = models.PositiveIntegerField(
        default=5, help_text="Days before due date to send first reminder"
    )

    urgent_reminder_days = models.PositiveIntegerField(
        default=1, help_text="Days before due date to send urgent reminder"
    )

    # Audit fields
    created_at = models.DateTimeField(
        default=timezone.now, help_text="When these settings were created"
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text="When these settings were last updated"
    )

    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Admin user who last updated these settings",
    )

    class Meta:
        db_table = "proof_of_life_settings"
        verbose_name = "Proof of Life Settings"
        verbose_name_plural = "Proof of Life Settings"

    def __str__(self):
        return f"Proof of Life Settings (Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M')})"

    def save(self, *args, **kwargs):
        """Ensure only one settings record exists."""
        if not self.pk and ProofOfLifeSettings.objects.exists():
            # Update existing record instead of creating new one
            existing = ProofOfLifeSettings.objects.first()
            if existing:
                existing.minimum_confidence_score = self.minimum_confidence_score
                existing.minimum_liveness_score = self.minimum_liveness_score
                existing.verification_interval_days = self.verification_interval_days
                existing.grace_period_days = self.grace_period_days
                existing.first_reminder_days = self.first_reminder_days
                existing.urgent_reminder_days = self.urgent_reminder_days
                existing.updated_by = self.updated_by
                existing.save()
                self.pk = existing.pk
        else:
            super().save(*args, **kwargs)

    @classmethod
    def get_settings(cls):
        """Get current settings, creating default if none exist."""
        settings, created = cls.objects.get_or_create(
            id=1,
            defaults={
                "minimum_confidence_score": Decimal("0.85"),
                "minimum_liveness_score": Decimal("0.80"),
                "verification_interval_days": 30,
                "grace_period_days": 3,
                "first_reminder_days": 5,
                "urgent_reminder_days": 1,
            },
        )
        return settings


class ProofOfLifeAuditLog(models.Model):
    """
    Audit log for proof of life verification attempts and admin actions.

    This model tracks all verification attempts (successful and failed)
    and administrative actions for compliance and security monitoring.
    """

    ACTION_CHOICES = [
        ("verification_attempt", "Verification Attempt"),
        ("verification_success", "Verification Success"),
        ("verification_failure", "Verification Failure"),
        ("status_update", "Status Update"),
        ("admin_override", "Admin Override"),
        ("settings_update", "Settings Update"),
    ]

    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the audit log entry",
    )

    # Related records
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="proof_of_life_audit_logs",
        null=True,
        blank=True,
        help_text="User associated with this action",
    )

    verification = models.ForeignKey(
        ProofOfLifeVerification,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        null=True,
        blank=True,
        help_text="Associated verification record if applicable",
    )

    # Action details
    action = models.CharField(
        max_length=50, choices=ACTION_CHOICES, help_text="Type of action performed"
    )

    description = models.TextField(help_text="Detailed description of the action")

    # Metadata
    metadata = models.JSONField(
        null=True,
        blank=True,
        help_text="Additional metadata about the action (scores, device info, etc.)",
    )

    # Request information
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address from which the action was performed",
    )

    user_agent = models.TextField(
        null=True, blank=True, help_text="User agent string from the request"
    )

    # Timestamps
    timestamp = models.DateTimeField(
        default=timezone.now, help_text="When this action occurred"
    )

    class Meta:
        db_table = "proof_of_life_audit_logs"
        verbose_name = "Proof of Life Audit Log"
        verbose_name_plural = "Proof of Life Audit Logs"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["user", "timestamp"]),
            models.Index(fields=["action", "timestamp"]),
            models.Index(fields=["timestamp"]),
        ]

    def __str__(self):
        user_info = f"{self.user.get_full_name()}" if self.user else "System"
        return f"{self.action} - {user_info} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    @classmethod
    def log_verification_attempt(
        cls,
        user,
        confidence_score,
        liveness_score,
        device_info,
        ip_address=None,
        user_agent=None,
    ):
        """Log a verification attempt with scores and device info."""
        return cls.objects.create(
            user=user,
            action="verification_attempt",
            description=f"Proof of life verification attempt by {user.get_full_name()}",
            metadata={
                "confidence_score": float(confidence_score),
                "liveness_score": float(liveness_score),
                "device_info": device_info,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @classmethod
    def log_verification_success(
        cls, user, verification, ip_address=None, user_agent=None
    ):
        """Log a successful verification."""
        return cls.objects.create(
            user=user,
            verification=verification,
            action="verification_success",
            description=f"Successful proof of life verification by {user.get_full_name()}",
            metadata={
                "verification_id": verification.verification_id,
                "confidence_score": float(verification.confidence_score),
                "liveness_score": float(verification.liveness_score),
                "next_due_date": verification.next_due_date.isoformat(),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @classmethod
    def log_verification_failure(
        cls, user, reason, metadata=None, ip_address=None, user_agent=None
    ):
        """Log a failed verification attempt."""
        return cls.objects.create(
            user=user,
            action="verification_failure",
            description=f"Failed proof of life verification by {user.get_full_name()}: {reason}",
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
