"""
Tests for proof of life views.
"""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.proof_of_life.models import (
    ProofOfLifeAuditLog,
    ProofOfLifePendingVerification,
    ProofOfLifeVerification,
)

User = get_user_model()


class BaseProofOfLifeTestCase(TestCase):
    """Base test case with common setup for proof of life tests."""

    def setUp(self):
        self.client: APIClient = APIClient()

        # Create test user
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            phone_number="+1234567890",
            nationality="Test",
            gender="M",
        )
        self.user.is_verified = True
        self.user.save()

        # Create admin user
        self.admin_user = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            phone_number="+1234567891",
            nationality="Test",
            gender="F",
        )

        # Set up authentication
        self.user_token = str(RefreshToken.for_user(self.user).access_token)
        self.admin_token = str(RefreshToken.for_user(self.admin_user).access_token)

        # Default device info for tests
        self.device_info = {
            "device_id": "test-device-123",
            "platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 12",
        }

        # Default verification data
        self.verification_data = {
            "confidence_score": "0.90",
            "liveness_score": "0.85",
            "device_info": self.device_info,
        }

    def authenticate_user(self):
        """Authenticate as regular user."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_token}")

    def authenticate_admin(self):
        """Authenticate as admin user."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")

    def create_verification(self, user=None, **kwargs):
        """Helper to create verification with defaults."""
        if user is None:
            user = self.user

        # Use a counter to ensure unique verification IDs
        if not hasattr(self, "_verification_counter"):
            self._verification_counter = 0
        self._verification_counter += 1

        defaults = {
            "user": user,
            "confidence_score": Decimal("0.90"),
            "liveness_score": Decimal("0.85"),
            "verification_date": timezone.now(),
            "device_id": f"test-device-view-{self._verification_counter}",
            "device_platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 12",
        }
        defaults.update(kwargs)

        # Ensure unique verification_id by pre-setting it
        if "verification_id" not in defaults:
            defaults["verification_id"] = (
                f"pol_view_test_{user.id.hex[:8]}_{self._verification_counter}"
            )

        return ProofOfLifeVerification.objects.create(**defaults)

    def create_pending_verification(self, user=None, **kwargs):
        """Helper to create pending verification with defaults."""
        if user is None:
            user = self.user

        # Use a counter to ensure unique session tokens
        if not hasattr(self, "_pending_counter"):
            self._pending_counter = 0
        self._pending_counter += 1

        defaults = {
            "user": user,
            "confidence_score": Decimal("0.90"),
            "liveness_score": Decimal("0.85"),
            "face_verification_timestamp": timezone.now(),
            "device_id": f"test-device-pending-view-{self._pending_counter}",
            "device_platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 12",
        }
        defaults.update(kwargs)

        # Ensure unique session_token by pre-setting it
        if "session_token" not in defaults:
            defaults["session_token"] = (
                f"polvf_view_test_{user.id.hex[:8]}_{self._pending_counter}"
            )

        return ProofOfLifePendingVerification.objects.create(**defaults)


class ProofOfLifeStatusViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeStatusView."""

    def test_get_status_no_verification(self):
        """Test getting status when user has no verifications."""
        self.authenticate_user()
        url = reverse("proof_of_life:status")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "overdue")
        self.assertTrue(data["is_overdue"])
        self.assertIsNone(data["next_due_date"])
        self.assertIsNone(data["last_verification_date"])

    def test_get_status_with_current_verification(self):
        """Test getting status with current verification."""
        self.authenticate_user()
        self.create_verification()
        url = reverse("proof_of_life:status")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "current")
        self.assertFalse(data["is_overdue"])
        self.assertIsNotNone(data["next_due_date"])
        self.assertIsNotNone(data["last_verification_date"])

    def test_get_status_overdue_verification(self):
        """Test getting status with overdue verification."""
        self.authenticate_user()
        past_date = timezone.now() - timedelta(days=35)
        self.create_verification(
            verification_date=past_date,
            next_due_date=timezone.now() - timedelta(days=2),
        )
        url = reverse("proof_of_life:status")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "overdue")
        self.assertTrue(data["is_overdue"])

    def test_get_status_blocked_verification(self):
        """Test getting status with blocked verification."""
        self.authenticate_user()
        past_date = timezone.now() - timedelta(days=35)
        self.create_verification(
            verification_date=past_date,
            next_due_date=timezone.now() - timedelta(days=5),
        )
        url = reverse("proof_of_life:status")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "blocked")
        self.assertTrue(data["is_overdue"])

    def test_get_status_unauthorized(self):
        """Test getting status without authentication."""
        url = reverse("proof_of_life:status")

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ProofOfLifeVerificationViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeVerificationView."""

    def test_submit_verification_success(self):
        """Test successful face verification submission."""
        self.authenticate_user()
        url = reverse("proof_of_life:verification")

        response = self.client.post(url, self.verification_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["face_verification_successful"])
        self.assertTrue(data["requires_otp"])
        self.assertIn("session_token", data)

        # Check pending verification was created
        self.assertTrue(
            ProofOfLifePendingVerification.objects.filter(
                user=self.user, session_token=data["session_token"]
            ).exists()
        )

    def test_submit_verification_insufficient_confidence(self):
        """Test verification with insufficient confidence score."""
        self.authenticate_user()
        url = reverse("proof_of_life:verification")

        # Low confidence score
        data = self.verification_data.copy()
        data["confidence_score"] = "0.75"  # Below 0.80 minimum

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "INSUFFICIENT_SCORES")
        self.assertFalse(response_data["face_verification_successful"])

    def test_submit_verification_insufficient_liveness(self):
        """Test verification with insufficient liveness score."""
        self.authenticate_user()
        url = reverse("proof_of_life:verification")

        # Low liveness score
        data = self.verification_data.copy()
        data["liveness_score"] = "0.65"  # Below 0.70 minimum

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "INSUFFICIENT_SCORES")

    def test_submit_verification_already_verified_this_month(self):
        """Test verification when user already verified this month."""
        self.authenticate_user()

        # Create recent verification
        self.create_verification(verification_date=timezone.now() - timedelta(days=15))

        url = reverse("proof_of_life:verification")
        response = self.client.post(url, self.verification_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error_code"], "ALREADY_VERIFIED")

    def test_submit_verification_invalid_data(self):
        """Test verification with invalid request data."""
        self.authenticate_user()
        url = reverse("proof_of_life:verification")

        # Missing required fields
        invalid_data = {"confidence_score": "0.90"}

        response = self.client.post(url, invalid_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error_code"], "INVALID_REQUEST")

    def test_submit_verification_clears_existing_pending(self):
        """Test that new verification clears existing pending verifications."""
        self.authenticate_user()

        # Create existing pending verification
        existing_pending = self.create_pending_verification()

        url = reverse("proof_of_life:verification")
        response = self.client.post(url, self.verification_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check old pending verification was deleted
        self.assertFalse(
            ProofOfLifePendingVerification.objects.filter(
                id=existing_pending.id
            ).exists()
        )


class ProofOfLifeOTPGenerateViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeOTPGenerateView."""

    @patch("apps.users.utils.OTPService.generate_otp")
    @patch("apps.users.tasks.send_otp_email.delay")
    def test_generate_otp_email_success(self, mock_send_email, mock_generate_otp):
        """Test successful OTP generation and sending via email."""
        self.authenticate_user()

        # Create pending verification
        pending = self.create_pending_verification()

        # Mock OTP service
        mock_otp = MagicMock()
        mock_otp.code = "123456"
        mock_otp.get_masked_contact.return_value = "te**@ex*****.com"
        mock_generate_otp.return_value = (True, mock_otp, "OTP generated")

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": pending.session_token, "method": "email"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data["success"])
        self.assertIn("OTP sent successfully", response_data["message"])

        # Check OTP service was called
        mock_generate_otp.assert_called_once_with(
            user_id=str(self.user.id), delivery_method="email"
        )

        # Check email task was called
        mock_send_email.assert_called_once()

        # Check pending verification was updated
        pending.refresh_from_db()
        self.assertTrue(pending.is_otp_sent)
        self.assertEqual(pending.otp_method, "email")

    @patch("apps.users.utils.OTPService.generate_otp")
    @patch("apps.users.tasks.send_otp_sms.delay")
    def test_generate_otp_sms_success(self, mock_send_sms, mock_generate_otp):
        """Test successful OTP generation and sending via SMS."""
        self.authenticate_user()

        # Create pending verification
        pending = self.create_pending_verification()

        # Mock OTP service
        mock_otp = MagicMock()
        mock_otp.code = "123456"
        mock_otp.get_masked_contact.return_value = "+123****890"
        mock_generate_otp.return_value = (True, mock_otp, "OTP generated")

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": pending.session_token, "method": "sms"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data["success"])

        # Check SMS task was called
        mock_send_sms.assert_called_once()

    def test_generate_otp_invalid_session_token(self):
        """Test OTP generation with invalid session token."""
        self.authenticate_user()

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": "invalid-token", "method": "email"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "INVALID_SESSION_TOKEN")

    def test_generate_otp_expired_session(self):
        """Test OTP generation with expired session."""
        self.authenticate_user()

        # Create expired pending verification
        past_time = timezone.now() - timedelta(minutes=15)
        pending = self.create_pending_verification(expires_at=past_time)

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": pending.session_token, "method": "email"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "SESSION_EXPIRED")

    def test_generate_otp_invalid_method(self):
        """Test OTP generation with invalid method."""
        self.authenticate_user()

        pending = self.create_pending_verification()

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": pending.session_token, "method": "invalid"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "INVALID_METHOD")

    def test_generate_otp_missing_parameters(self):
        """Test OTP generation with missing parameters."""
        self.authenticate_user()

        url = reverse("proof_of_life:otp_generate")
        data = {"session_token": "token"}  # Missing method

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "MISSING_PARAMETERS")


class ProofOfLifeOTPVerifyViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeOTPVerifyView."""

    @patch("apps.users.utils.OTPService.verify_otp")
    def test_verify_otp_success(self, mock_verify_otp):
        """Test successful OTP verification."""
        self.authenticate_user()

        # Create pending verification with OTP sent
        pending = self.create_pending_verification()
        pending.mark_otp_sent("email")

        # Mock OTP service
        mock_verify_otp.return_value = (True, self.user, "OTP verified")

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": pending.session_token, "otp_code": "123456"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data["success"])
        self.assertIn("verification_id", response_data)
        self.assertIn("next_due_date", response_data)

        # Check verification was created
        self.assertTrue(
            ProofOfLifeVerification.objects.filter(
                user=self.user, verification_id=response_data["verification_id"]
            ).exists()
        )

        # Check pending verification was deleted
        self.assertFalse(
            ProofOfLifePendingVerification.objects.filter(id=pending.id).exists()
        )

    @patch("apps.users.utils.OTPService.verify_otp")
    def test_verify_otp_invalid_code(self, mock_verify_otp):
        """Test OTP verification with invalid code."""
        self.authenticate_user()

        # Create pending verification with OTP sent
        pending = self.create_pending_verification()
        pending.mark_otp_sent("email")

        # Mock OTP service failure
        mock_verify_otp.return_value = (False, None, "Invalid OTP code")

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": pending.session_token, "otp_code": "wrong"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "OTP_VERIFICATION_FAILED")

    def test_verify_otp_invalid_session_token(self):
        """Test OTP verification with invalid session token."""
        self.authenticate_user()

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": "invalid-token", "otp_code": "123456"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "INVALID_SESSION_TOKEN")

    def test_verify_otp_expired_session(self):
        """Test OTP verification with expired session."""
        self.authenticate_user()

        # Create expired pending verification
        past_time = timezone.now() - timedelta(minutes=15)
        pending = self.create_pending_verification(expires_at=past_time)
        pending.mark_otp_sent("email")

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": pending.session_token, "otp_code": "123456"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "SESSION_EXPIRED")

    def test_verify_otp_not_sent(self):
        """Test OTP verification when OTP was not sent."""
        self.authenticate_user()

        # Create pending verification without OTP sent
        pending = self.create_pending_verification()

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": pending.session_token, "otp_code": "123456"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "OTP_NOT_SENT")

    def test_verify_otp_missing_parameters(self):
        """Test OTP verification with missing parameters."""
        self.authenticate_user()

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": "token"}  # Missing otp_code

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data["success"])
        self.assertEqual(response_data["error_code"], "MISSING_PARAMETERS")


class ProofOfLifeHistoryViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeHistoryView."""

    def test_get_history_success(self):
        """Test getting verification history."""
        self.authenticate_user()

        # Create multiple verifications
        for i in range(5):
            self.create_verification(
                verification_date=timezone.now() - timedelta(days=i * 30)
            )

        url = reverse("proof_of_life:history")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["records"]), 5)
        self.assertEqual(data["total"], 5)
        self.assertFalse(data["has_more"])

    def test_get_history_pagination(self):
        """Test getting verification history with pagination."""
        self.authenticate_user()

        # Create 15 verifications
        for i in range(15):
            self.create_verification(
                verification_date=timezone.now() - timedelta(days=i * 30)
            )

        url = reverse("proof_of_life:history")
        response = self.client.get(url, {"limit": 10, "offset": 0})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["records"]), 10)
        self.assertEqual(data["total"], 15)
        self.assertTrue(data["has_more"])

    def test_get_history_no_verifications(self):
        """Test getting history when user has no verifications."""
        self.authenticate_user()

        url = reverse("proof_of_life:history")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["records"]), 0)
        self.assertEqual(data["total"], 0)
        self.assertFalse(data["has_more"])


class ProofOfLifeAdminViewTest(BaseProofOfLifeTestCase):
    """Tests for ProofOfLifeAdminView."""

    def test_get_all_verifications_admin(self):
        """Test getting all verifications as admin."""
        self.authenticate_admin()

        # Create verifications for multiple users
        user2 = User.objects.create_user(
            email="user2@test.com",
            password="testpass123",
            first_name="User",
            last_name="Two",
            phone_number="+1234567892",
            nationality="Test",
            gender="M",
        )

        self.create_verification(user=self.user)
        self.create_verification(user=user2)

        url = reverse("proof_of_life:admin")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["data"]), 2)
        self.assertEqual(data["total"], 2)

    def test_get_verifications_with_status_filter(self):
        """Test getting verifications with status filter."""
        self.authenticate_admin()

        # Create verifications with different statuses
        self.create_verification(status="current")
        self.create_verification(status="overdue")

        url = reverse("proof_of_life:admin")
        response = self.client.get(url, {"status": "current"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["data"]), 1)
        self.assertEqual(data["data"][0]["status"], "current")

    def test_get_verifications_non_admin(self):
        """Test getting verifications as non-admin user."""
        self.authenticate_user()

        url = reverse("proof_of_life:admin")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_verifications_pagination(self):
        """Test getting verifications with pagination."""
        self.authenticate_admin()

        # Create multiple verifications
        for _ in range(15):
            self.create_verification()

        url = reverse("proof_of_life:admin")
        response = self.client.get(url, {"limit": 10, "offset": 5})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["data"]), 10)
        self.assertEqual(data["total"], 15)
        self.assertEqual(data["offset"], 5)


class ProofOfLifeAuditLoggingTest(BaseProofOfLifeTestCase):
    """Tests for audit logging in proof of life views."""

    def test_verification_attempt_logged(self):
        """Test that verification attempts are logged."""
        self.authenticate_user()

        url = reverse("proof_of_life:verification")
        response = self.client.post(url, self.verification_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check audit log was created
        self.assertTrue(
            ProofOfLifeAuditLog.objects.filter(
                user=self.user, action="verification_attempt"
            ).exists()
        )

    @patch("apps.users.utils.OTPService.verify_otp")
    def test_verification_success_logged(self, mock_verify_otp):
        """Test that successful verifications are logged."""
        self.authenticate_user()

        # Create pending verification
        pending = self.create_pending_verification()
        pending.mark_otp_sent("email")

        # Mock OTP service
        mock_verify_otp.return_value = (True, self.user, "OTP verified")

        url = reverse("proof_of_life:otp_verify")
        data = {"session_token": pending.session_token, "otp_code": "123456"}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check audit log was created
        self.assertTrue(
            ProofOfLifeAuditLog.objects.filter(
                user=self.user, action="verification_success"
            ).exists()
        )

    def test_verification_failure_logged(self):
        """Test that verification failures are logged."""
        self.authenticate_user()

        # Submit verification with insufficient scores
        url = reverse("proof_of_life:verification")
        data = self.verification_data.copy()
        data["confidence_score"] = "0.75"  # Below minimum

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check audit log was created
        self.assertTrue(
            ProofOfLifeAuditLog.objects.filter(
                user=self.user, action="verification_failure"
            ).exists()
        )
