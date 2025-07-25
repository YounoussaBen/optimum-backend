"""
Tests for proof of life models.
"""

from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.proof_of_life.models import (
    ProofOfLifeAuditLog,
    ProofOfLifePendingVerification,
    ProofOfLifeSettings,
    ProofOfLifeVerification,
)

User = get_user_model()


class ProofOfLifeModelsTestCase(TestCase):
    """Base test case for proof of life models."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            phone_number="+1234567890",
            nationality="Test",
            gender="M",
        )

    def create_verification(self, **kwargs):
        """Helper to create verification with defaults."""
        # Use a counter to ensure unique verification IDs
        if not hasattr(self, "_verification_counter"):
            self._verification_counter = 0
        self._verification_counter += 1

        defaults = {
            "user": self.user,
            "confidence_score": Decimal("0.90"),
            "liveness_score": Decimal("0.85"),
            "verification_date": timezone.now(),
            "device_id": f"test-device-{self._verification_counter}",
            "device_platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 12",
        }
        defaults.update(kwargs)

        # Ensure unique verification_id by pre-setting it
        if "verification_id" not in defaults:
            defaults["verification_id"] = (
                f"pol_test_{self.user.id.hex[:8]}_{self._verification_counter}"
            )

        return ProofOfLifeVerification.objects.create(**defaults)

    def create_pending_verification(self, **kwargs):
        """Helper to create pending verification with defaults."""
        # Use a counter to ensure unique session tokens
        if not hasattr(self, "_pending_counter"):
            self._pending_counter = 0
        self._pending_counter += 1

        defaults = {
            "user": self.user,
            "confidence_score": Decimal("0.90"),
            "liveness_score": Decimal("0.85"),
            "face_verification_timestamp": timezone.now(),
            "device_id": f"test-device-pending-{self._pending_counter}",
            "device_platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 12",
        }
        defaults.update(kwargs)

        # Ensure unique session_token by pre-setting it
        if "session_token" not in defaults:
            defaults["session_token"] = (
                f"polvf_test_{self.user.id.hex[:8]}_{self._pending_counter}"
            )

        return ProofOfLifePendingVerification.objects.create(**defaults)


class ProofOfLifeVerificationModelTest(ProofOfLifeModelsTestCase):
    """Tests for ProofOfLifeVerification model."""

    def test_create_verification(self):
        """Test creating a verification record."""
        verification = self.create_verification()

        self.assertIsNotNone(verification.id)
        self.assertIsNotNone(verification.verification_id)
        self.assertIsNotNone(verification.next_due_date)
        self.assertEqual(verification.user, self.user)
        self.assertEqual(verification.status, "current")

    def test_verification_id_generation(self):
        """Test automatic verification ID generation."""
        verification = self.create_verification()
        expected_prefix = f"pol_test_{self.user.id.hex[:8]}"
        self.assertTrue(verification.verification_id.startswith(expected_prefix))

    def test_next_due_date_calculation(self):
        """Test next due date is set to 30 days from verification."""
        verification_date = timezone.now()
        verification = self.create_verification(verification_date=verification_date)
        expected_due_date = verification_date + timedelta(days=30)

        # Compare dates (ignore microseconds)
        self.assertEqual(verification.next_due_date.date(), expected_due_date.date())

    def test_is_verification_successful_property(self):
        """Test verification success property."""
        # Successful verification
        verification = self.create_verification(
            confidence_score=Decimal("0.90"), liveness_score=Decimal("0.85")
        )
        self.assertTrue(verification.is_verification_successful)

        # Failed verification - low confidence
        verification = self.create_verification(
            confidence_score=Decimal("0.80"), liveness_score=Decimal("0.85")
        )
        self.assertFalse(verification.is_verification_successful)

        # Failed verification - low liveness
        verification = self.create_verification(
            confidence_score=Decimal("0.90"), liveness_score=Decimal("0.75")
        )
        self.assertFalse(verification.is_verification_successful)

    def test_days_until_due_property(self):
        """Test days until due calculation."""
        # Verification due in 10 days
        future_date = timezone.now() + timedelta(days=10)
        verification = self.create_verification(next_due_date=future_date)
        self.assertEqual(verification.days_until_due, 10)

        # Verification overdue by 5 days
        past_date = timezone.now() - timedelta(days=5)
        verification = self.create_verification(next_due_date=past_date)
        self.assertEqual(verification.days_until_due, -5)

    def test_is_overdue_property(self):
        """Test overdue property."""
        # Not overdue
        future_date = timezone.now() + timedelta(days=10)
        verification = self.create_verification(next_due_date=future_date)
        self.assertFalse(verification.is_overdue)

        # Overdue
        past_date = timezone.now() - timedelta(days=5)
        verification = self.create_verification(next_due_date=past_date)
        self.assertTrue(verification.is_overdue)

    def test_urgency_level_property(self):
        """Test urgency level calculation."""
        # No urgency (> 5 days)
        verification = self.create_verification(
            next_due_date=timezone.now() + timedelta(days=10)
        )
        self.assertEqual(verification.urgency_level, 0)

        # Due soon (1-5 days)
        verification = self.create_verification(
            next_due_date=timezone.now() + timedelta(days=3)
        )
        self.assertEqual(verification.urgency_level, 1)

        # Overdue (-3 to 0 days)
        verification = self.create_verification(
            next_due_date=timezone.now() - timedelta(days=1)
        )
        self.assertEqual(verification.urgency_level, 2)

        # Critical (< -3 days)
        verification = self.create_verification(
            next_due_date=timezone.now() - timedelta(days=5)
        )
        self.assertEqual(verification.urgency_level, 3)

    def test_update_status_method(self):
        """Test status update based on due date."""
        # Current status
        verification = self.create_verification(
            next_due_date=timezone.now() + timedelta(days=10)
        )
        status = verification.update_status()
        self.assertEqual(status, "current")

        # Due soon status
        verification = self.create_verification(
            next_due_date=timezone.now() + timedelta(days=3)
        )
        status = verification.update_status()
        self.assertEqual(status, "due_soon")

        # Overdue status
        verification = self.create_verification(
            next_due_date=timezone.now() - timedelta(days=1)
        )
        status = verification.update_status()
        self.assertEqual(status, "overdue")

        # Blocked status
        verification = self.create_verification(
            next_due_date=timezone.now() - timedelta(days=5)
        )
        status = verification.update_status()
        self.assertEqual(status, "blocked")

    def test_str_representation(self):
        """Test string representation."""
        verification = self.create_verification()
        expected = f"Proof of Life - {self.user.get_full_name()} - {verification.verification_date.strftime('%Y-%m-%d')}"
        self.assertEqual(str(verification), expected)


class ProofOfLifePendingVerificationModelTest(ProofOfLifeModelsTestCase):
    """Tests for ProofOfLifePendingVerification model."""

    def test_create_pending_verification(self):
        """Test creating a pending verification record."""
        pending = self.create_pending_verification()

        self.assertIsNotNone(pending.id)
        self.assertIsNotNone(pending.session_token)
        self.assertIsNotNone(pending.expires_at)
        self.assertEqual(pending.user, self.user)
        self.assertFalse(pending.is_otp_sent)

    def test_session_token_generation(self):
        """Test automatic session token generation."""
        pending = self.create_pending_verification()
        expected_prefix = f"polvf_test_{self.user.id.hex[:8]}"
        self.assertTrue(pending.session_token.startswith(expected_prefix))

    def test_expires_at_calculation(self):
        """Test expiration time is set to 10 minutes from face verification."""
        face_time = timezone.now()
        pending = self.create_pending_verification(
            face_verification_timestamp=face_time
        )
        expected_expiry = face_time + timedelta(minutes=10)

        # Compare timestamps (ignore microseconds)
        self.assertEqual(
            pending.expires_at.replace(microsecond=0),
            expected_expiry.replace(microsecond=0),
        )

    def test_is_expired_property(self):
        """Test expired property."""
        # Not expired
        future_time = timezone.now() + timedelta(minutes=5)
        pending = self.create_pending_verification(expires_at=future_time)
        self.assertFalse(pending.is_expired)

        # Expired
        past_time = timezone.now() - timedelta(minutes=5)
        pending = self.create_pending_verification(expires_at=past_time)
        self.assertTrue(pending.is_expired)

    def test_is_face_verification_successful_property(self):
        """Test face verification success property."""
        # Get settings to ensure they exist
        ProofOfLifeSettings.get_settings()

        # Successful verification
        pending = self.create_pending_verification(
            confidence_score=Decimal("0.90"), liveness_score=Decimal("0.85")
        )
        self.assertTrue(pending.is_face_verification_successful)

        # Failed verification
        pending = self.create_pending_verification(
            confidence_score=Decimal("0.80"), liveness_score=Decimal("0.75")
        )
        self.assertFalse(pending.is_face_verification_successful)

    def test_mark_otp_sent_method(self):
        """Test marking OTP as sent."""
        pending = self.create_pending_verification()
        self.assertFalse(pending.is_otp_sent)
        self.assertIsNone(pending.otp_method)

        pending.mark_otp_sent("email")
        pending.refresh_from_db()

        self.assertTrue(pending.is_otp_sent)
        self.assertEqual(pending.otp_method, "email")

    def test_convert_to_full_verification(self):
        """Test converting pending verification to full verification."""
        pending = self.create_pending_verification(
            confidence_score=Decimal("0.90"), liveness_score=Decimal("0.85")
        )

        # Convert to full verification
        verification = pending.convert_to_full_verification()

        # Check verification was created
        self.assertIsInstance(verification, ProofOfLifeVerification)
        self.assertEqual(verification.user, self.user)
        self.assertEqual(verification.confidence_score, Decimal("0.90"))
        self.assertEqual(verification.liveness_score, Decimal("0.85"))

        # Check pending verification was deleted
        with self.assertRaises(ProofOfLifePendingVerification.DoesNotExist):
            pending.refresh_from_db()

    def test_convert_to_full_verification_expired(self):
        """Test conversion fails if pending verification is expired."""
        past_time = timezone.now() - timedelta(minutes=15)
        pending = self.create_pending_verification(
            expires_at=past_time,
            confidence_score=Decimal("0.90"),
            liveness_score=Decimal("0.85"),
        )

        with self.assertRaises(ValueError) as context:
            pending.convert_to_full_verification()

        self.assertIn("expired", str(context.exception))

    def test_convert_to_full_verification_insufficient_scores(self):
        """Test conversion fails if scores are insufficient."""
        pending = self.create_pending_verification(
            confidence_score=Decimal("0.80"), liveness_score=Decimal("0.75")
        )

        with self.assertRaises(ValueError) as context:
            pending.convert_to_full_verification()

        self.assertIn("minimum requirements", str(context.exception))

    def test_str_representation(self):
        """Test string representation."""
        pending = self.create_pending_verification()
        expected = f"Pending Verification - {self.user.get_full_name()} - {pending.created_at.strftime('%Y-%m-%d %H:%M')}"
        self.assertEqual(str(pending), expected)


class ProofOfLifeSettingsModelTest(TestCase):
    """Tests for ProofOfLifeSettings model."""

    def test_singleton_pattern(self):
        """Test that only one settings record can exist."""
        # Create first settings
        settings1 = ProofOfLifeSettings.objects.create(
            minimum_confidence_score=Decimal("0.85"),
            minimum_liveness_score=Decimal("0.80"),
        )

        # Try to create second settings - should update first instead
        settings2 = ProofOfLifeSettings(
            minimum_confidence_score=Decimal("0.90"),
            minimum_liveness_score=Decimal("0.85"),
        )
        settings2.save()

        # Should still be only one record
        self.assertEqual(ProofOfLifeSettings.objects.count(), 1)

        # Settings should be updated
        settings1.refresh_from_db()
        self.assertEqual(settings1.minimum_confidence_score, Decimal("0.90"))
        self.assertEqual(settings1.minimum_liveness_score, Decimal("0.85"))

    def test_get_settings_creates_default(self):
        """Test get_settings creates default settings if none exist."""
        # Ensure no settings exist
        ProofOfLifeSettings.objects.all().delete()

        settings = ProofOfLifeSettings.get_settings()

        self.assertIsNotNone(settings)
        self.assertEqual(settings.minimum_confidence_score, Decimal("0.85"))
        self.assertEqual(settings.minimum_liveness_score, Decimal("0.80"))
        self.assertEqual(settings.verification_interval_days, 30)

    def test_get_settings_returns_existing(self):
        """Test get_settings returns existing settings."""
        # Create custom settings
        existing = ProofOfLifeSettings.objects.create(
            minimum_confidence_score=Decimal("0.95"),
            minimum_liveness_score=Decimal("0.90"),
        )

        settings = ProofOfLifeSettings.get_settings()

        self.assertEqual(settings.id, existing.id)
        self.assertEqual(settings.minimum_confidence_score, Decimal("0.95"))

    def test_str_representation(self):
        """Test string representation."""
        settings = ProofOfLifeSettings.get_settings()
        expected = f"Proof of Life Settings (Updated: {settings.updated_at.strftime('%Y-%m-%d %H:%M')})"
        self.assertEqual(str(settings), expected)


class ProofOfLifeAuditLogModelTest(ProofOfLifeModelsTestCase):
    """Tests for ProofOfLifeAuditLog model."""

    def test_create_audit_log(self):
        """Test creating an audit log entry."""
        log = ProofOfLifeAuditLog.objects.create(
            user=self.user,
            action="verification_attempt",
            description="Test verification attempt",
            metadata={"test": "data"},
            ip_address="127.0.0.1",
        )

        self.assertIsNotNone(log.id)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, "verification_attempt")
        self.assertIsNotNone(log.timestamp)

    def test_log_verification_attempt_classmethod(self):
        """Test log_verification_attempt class method."""
        device_info = {"device_id": "test-device", "platform": "android"}

        log = ProofOfLifeAuditLog.log_verification_attempt(
            user=self.user,
            confidence_score=Decimal("0.90"),
            liveness_score=Decimal("0.85"),
            device_info=device_info,
            ip_address="127.0.0.1",
        )

        self.assertEqual(log.action, "verification_attempt")
        self.assertEqual(log.user, self.user)
        self.assertIn("confidence_score", log.metadata)
        self.assertIn("device_info", log.metadata)

    def test_log_verification_success_classmethod(self):
        """Test log_verification_success class method."""
        verification = self.create_verification()

        log = ProofOfLifeAuditLog.log_verification_success(
            user=self.user, verification=verification, ip_address="127.0.0.1"
        )

        self.assertEqual(log.action, "verification_success")
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.verification, verification)
        self.assertIn("verification_id", log.metadata)

    def test_log_verification_failure_classmethod(self):
        """Test log_verification_failure class method."""
        log = ProofOfLifeAuditLog.log_verification_failure(
            user=self.user,
            reason="Low confidence score",
            metadata={"confidence": 0.75},
            ip_address="127.0.0.1",
        )

        self.assertEqual(log.action, "verification_failure")
        self.assertEqual(log.user, self.user)
        self.assertIn("Low confidence score", log.description)
        self.assertIn("confidence", log.metadata)

    def test_str_representation(self):
        """Test string representation."""
        log = ProofOfLifeAuditLog.objects.create(
            user=self.user, action="verification_attempt", description="Test log entry"
        )

        expected = f"verification_attempt - {self.user.get_full_name()} - {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        self.assertEqual(str(log), expected)

    def test_str_representation_no_user(self):
        """Test string representation with no user."""
        log = ProofOfLifeAuditLog.objects.create(
            action="settings_update", description="System updated settings"
        )

        expected = (
            f"settings_update - System - {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.assertEqual(str(log), expected)
