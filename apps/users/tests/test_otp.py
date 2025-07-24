"""
Comprehensive tests for OTP authentication functionality.
"""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.users.models import OTP
from apps.users.utils import OTPService

User = get_user_model()


class BaseOTPTestCase(TestCase):
    """Base test case with common setup for OTP tests."""

    def setUp(self):
        self.client = APIClient()

        # Create test user
        self.user = User.objects.create_user(
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
            phone_number="+241012345678",
            nationality="Gabon",
            gender="M",
        )

        # Create inactive user for testing
        self.inactive_user = User.objects.create_user(
            email="inactive@example.com",
            first_name="Inactive",
            last_name="User",
            phone_number="+241012345679",
            nationality="Gabon",
            gender="F",
            is_active=False,
        )


class OTPModelTest(BaseOTPTestCase):
    """Test OTP model functionality."""

    def test_otp_creation(self):
        """Test OTP instance creation."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")

        self.assertIsNotNone(otp.id)
        self.assertEqual(otp.user, self.user)
        self.assertEqual(otp.delivery_method, "email")
        self.assertEqual(len(otp.code), 6)
        self.assertTrue(otp.code.isdigit())
        self.assertFalse(otp.is_used)
        self.assertFalse(otp.is_expired)
        self.assertIsNotNone(otp.expires_at)

    def test_otp_auto_expires_in_60_seconds(self):
        """Test that OTP expires after 60 seconds."""
        otp = OTP.objects.create(user=self.user, delivery_method="sms")

        expected_expiry = timezone.now() + timedelta(seconds=60)
        # Allow 1 second tolerance for test timing
        self.assertAlmostEqual(
            otp.expires_at.timestamp(), expected_expiry.timestamp(), delta=1
        )

    def test_otp_generates_unique_codes(self):
        """Test that each OTP generates a unique code."""
        otp1 = OTP.objects.create(user=self.user, delivery_method="email")
        otp2 = OTP.objects.create(user=self.user, delivery_method="sms")

        self.assertNotEqual(otp1.code, otp2.code)

    def test_otp_is_valid_property(self):
        """Test OTP is_valid property."""
        # Valid OTP
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        self.assertTrue(otp.is_valid)

        # Used OTP
        otp.mark_as_used()
        self.assertFalse(otp.is_valid)

        # Expired OTP
        otp2 = OTP.objects.create(user=self.user, delivery_method="sms")
        otp2.is_expired = True
        otp2.save()
        self.assertFalse(otp2.is_valid)

    def test_otp_mark_as_used(self):
        """Test marking OTP as used."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")

        self.assertFalse(otp.is_used)
        self.assertIsNone(otp.used_at)

        otp.mark_as_used()

        self.assertTrue(otp.is_used)
        self.assertIsNotNone(otp.used_at)

    def test_otp_get_masked_contact_email(self):
        """Test email contact masking."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        masked_email = otp.get_masked_contact()

        # Should mask email like t*******r@example.com
        self.assertIn("@", masked_email)
        self.assertIn("*", masked_email)
        self.assertTrue(masked_email.endswith("@example.com"))

    def test_otp_get_masked_contact_sms(self):
        """Test SMS contact masking."""
        otp = OTP.objects.create(user=self.user, delivery_method="sms")
        masked_phone = otp.get_masked_contact()

        # Should mask phone number
        self.assertIn("*", masked_phone)

    def test_otp_string_representation(self):
        """Test OTP string representation."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        expected_str = f"OTP for {self.user.email} via email - {otp.code}"
        self.assertEqual(str(otp), expected_str)


class OTPServiceTest(BaseOTPTestCase):
    """Test OTP service functionality."""

    def test_generate_otp_success_email(self):
        """Test successful OTP generation for email."""
        success, otp_instance, message = OTPService.generate_otp(
            user_id=str(self.user.id), delivery_method="email"
        )

        self.assertTrue(success)
        self.assertIsNotNone(otp_instance)
        self.assertEqual(message, "OTP generated successfully")
        self.assertIsNotNone(otp_instance)
        self.assertEqual(otp_instance.user, self.user)  # type: ignore
        self.assertEqual(otp_instance.delivery_method, "email")  # type: ignore

    def test_generate_otp_success_sms(self):
        """Test successful OTP generation for SMS."""
        success, otp_instance, message = OTPService.generate_otp(
            user_id=str(self.user.id), delivery_method="sms"
        )

        self.assertTrue(success)
        self.assertIsNotNone(otp_instance)
        self.assertEqual(message, "OTP generated successfully")
        self.assertIsNotNone(otp_instance)
        self.assertEqual(otp_instance.delivery_method, "sms")  # type: ignore

    def test_generate_otp_invalid_user(self):
        """Test OTP generation with invalid user ID."""
        success, otp_instance, message = OTPService.generate_otp(
            user_id=str(uuid.uuid4()), delivery_method="email"
        )

        self.assertFalse(success)
        self.assertIsNone(otp_instance)
        self.assertEqual(message, "User not found or inactive")

    def test_generate_otp_inactive_user(self):
        """Test OTP generation for inactive user."""
        success, otp_instance, message = OTPService.generate_otp(
            user_id=str(self.inactive_user.id), delivery_method="email"
        )

        self.assertFalse(success)
        self.assertIsNone(otp_instance)
        self.assertEqual(message, "User not found or inactive")

    def test_generate_otp_invalid_method(self):
        """Test OTP generation with invalid delivery method."""
        success, otp_instance, message = OTPService.generate_otp(
            user_id=str(self.user.id), delivery_method="invalid"
        )

        self.assertFalse(success)
        self.assertIsNone(otp_instance)
        self.assertEqual(message, "Invalid delivery method. Must be 'sms' or 'email'")

    def test_generate_otp_invalidates_existing(self):
        """Test that generating new OTP invalidates existing ones."""
        # Create first OTP
        first_otp = OTP.objects.create(user=self.user, delivery_method="email")
        self.assertTrue(first_otp.is_valid)

        # Generate new OTP
        success, new_otp, message = OTPService.generate_otp(
            user_id=str(self.user.id), delivery_method="email"
        )

        self.assertTrue(success)

        # Check that first OTP is now expired
        first_otp.refresh_from_db()
        self.assertTrue(first_otp.is_expired)

    def test_verify_otp_success(self):
        """Test successful OTP verification."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")

        success, user_instance, message = OTPService.verify_otp(
            user_id=str(self.user.id), otp_code=otp.code
        )

        self.assertTrue(success)
        self.assertEqual(user_instance, self.user)
        self.assertEqual(message, "OTP verified successfully")

        # Check that OTP is marked as used
        otp.refresh_from_db()
        self.assertTrue(otp.is_used)

    def test_verify_otp_invalid_user(self):
        """Test OTP verification with invalid user ID."""
        success, user_instance, message = OTPService.verify_otp(
            user_id=str(uuid.uuid4()), otp_code="123456"
        )

        self.assertFalse(success)
        self.assertIsNone(user_instance)
        self.assertEqual(message, "User not found or inactive")

    def test_verify_otp_invalid_code(self):
        """Test OTP verification with invalid code."""
        OTP.objects.create(user=self.user, delivery_method="email")

        success, user_instance, message = OTPService.verify_otp(
            user_id=str(self.user.id), otp_code="000000"
        )

        self.assertFalse(success)
        self.assertIsNone(user_instance)
        self.assertEqual(message, "Invalid OTP code")

    def test_verify_otp_used_code(self):
        """Test OTP verification with already used code."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        otp.mark_as_used()

        success, user_instance, message = OTPService.verify_otp(
            user_id=str(self.user.id), otp_code=otp.code
        )

        self.assertFalse(success)
        self.assertIsNone(user_instance)
        self.assertEqual(message, "Invalid OTP code")

    def test_verify_otp_expired_code(self):
        """Test OTP verification with expired code."""
        # Create expired OTP
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        otp.expires_at = timezone.now() - timedelta(seconds=1)
        otp.save()

        success, user_instance, message = OTPService.verify_otp(
            user_id=str(self.user.id), otp_code=otp.code
        )

        self.assertFalse(success)
        self.assertIsNone(user_instance)
        self.assertEqual(message, "Invalid OTP code")

    def test_cleanup_expired_otps(self):
        """Test cleanup of expired OTPs."""
        # Create valid OTP
        valid_otp = OTP.objects.create(user=self.user, delivery_method="email")

        # Create expired OTP
        expired_otp = OTP.objects.create(user=self.user, delivery_method="sms")
        expired_otp.expires_at = timezone.now() - timedelta(seconds=1)
        expired_otp.save()

        # Create old OTP (should be deleted)
        old_otp = OTP.objects.create(user=self.user, delivery_method="email")
        old_otp.created_at = timezone.now() - timedelta(hours=25)
        old_otp.save()

        result = OTPService.cleanup_expired_otps()

        self.assertIn("Marked", result)
        self.assertIn("deleted", result)

        # Check that expired OTP is marked as expired
        expired_otp.refresh_from_db()
        self.assertTrue(expired_otp.is_expired)

        # Check that old OTP is deleted
        self.assertFalse(OTP.objects.filter(id=old_otp.id).exists())

        # Check that valid OTP still exists
        self.assertTrue(OTP.objects.filter(id=valid_otp.id).exists())


class GenerateOTPViewTest(BaseOTPTestCase):
    """Test GenerateOTPView endpoint."""

    def setUp(self):
        super().setUp()
        self.url = reverse("users:generate-otp")

    @patch("apps.users.otp_views.send_otp_email.delay")
    def test_generate_otp_email_success(self, mock_email_task):
        """Test successful OTP generation and email sending."""
        data = {"user_id": str(self.user.id), "method": "email"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])  # type: ignore
        self.assertEqual(response.data["message"], "OTP sent successfully")  # type: ignore
        self.assertIn("contact", response.data)  # type: ignore
        self.assertEqual(response.data["expires_in"], 60)  # type: ignore

        # Check that email task was called
        mock_email_task.assert_called_once()

        # Check that OTP was created in database
        self.assertTrue(
            OTP.objects.filter(user=self.user, delivery_method="email").exists()
        )

    @patch("apps.users.otp_views.send_otp_sms.delay")
    def test_generate_otp_sms_success(self, mock_sms_task):
        """Test successful OTP generation and SMS sending."""
        data = {"user_id": str(self.user.id), "method": "sms"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])  # type: ignore
        self.assertEqual(response.data["message"], "OTP sent successfully")  # type: ignore

        # Check that SMS task was called
        mock_sms_task.assert_called_once()

    def test_generate_otp_invalid_user(self):
        """Test OTP generation with invalid user ID."""
        data = {"user_id": str(uuid.uuid4()), "method": "email"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # When serializer validation fails, DRF returns field errors
        self.assertIn("user_id", response.data)  # type: ignore

    def test_generate_otp_inactive_user(self):
        """Test OTP generation for inactive user."""
        data = {"user_id": str(self.inactive_user.id), "method": "email"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # When serializer validation fails, DRF returns field errors
        self.assertIn("user_id", response.data)  # type: ignore

    def test_generate_otp_invalid_method(self):
        """Test OTP generation with invalid method."""
        data = {"user_id": str(self.user.id), "method": "invalid"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_otp_missing_fields(self):
        """Test OTP generation with missing required fields."""
        # Missing user_id
        response = self.client.post(self.url, {"method": "email"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Missing method
        response = self.client.post(
            self.url, {"user_id": str(self.user.id)}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_generate_otp_invalid_uuid(self):
        """Test OTP generation with invalid UUID format."""
        data = {"user_id": "invalid-uuid", "method": "email"}

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "apps.users.otp_views.send_otp_email.delay",
        side_effect=Exception("Task failed"),
    )
    def test_generate_otp_task_failure(self, mock_email_task):
        """Test OTP generation when background task fails."""
        data = {"user_id": str(self.user.id), "method": "email"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertFalse(response.data["success"])  # type: ignore
        self.assertIn("Failed to send OTP", response.data["message"])  # type: ignore


class VerifyOTPViewTest(BaseOTPTestCase):
    """Test VerifyOTPView endpoint."""

    def setUp(self):
        super().setUp()
        self.url = reverse("users:verify-otp")

    def test_verify_otp_success(self):
        """Test successful OTP verification."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")

        data = {"user_id": str(self.user.id), "otp_code": otp.code}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])  # type: ignore
        self.assertEqual(response.data["message"], "Authentication successful")  # type: ignore
        self.assertIn("access_token", response.data)  # type: ignore
        self.assertIn("refresh_token", response.data)  # type: ignore
        self.assertIn("user", response.data)  # type: ignore

        # Check user data in response
        user_data = response.data["user"]  # type: ignore
        self.assertEqual(user_data["id"], str(self.user.id))
        self.assertEqual(user_data["name"], self.user.get_full_name())
        self.assertEqual(user_data["email"], self.user.email)
        self.assertEqual(user_data["phone"], self.user.phone_number)

    def test_verify_otp_invalid_user(self):
        """Test OTP verification with invalid user ID."""
        data = {"user_id": str(uuid.uuid4()), "otp_code": "123456"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # When serializer validation fails, DRF returns field errors
        self.assertIn("user_id", response.data)  # type: ignore

    def test_verify_otp_inactive_user(self):
        """Test OTP verification for inactive user."""
        otp = OTP.objects.create(user=self.inactive_user, delivery_method="email")

        data = {"user_id": str(self.inactive_user.id), "otp_code": otp.code}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # When serializer validation fails, DRF returns field errors
        self.assertIn("user_id", response.data)  # type: ignore

    def test_verify_otp_invalid_code(self):
        """Test OTP verification with invalid code."""
        OTP.objects.create(user=self.user, delivery_method="email")

        data = {"user_id": str(self.user.id), "otp_code": "000000"}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data["success"])  # type: ignore

    def test_verify_otp_expired_code(self):
        """Test OTP verification with expired code."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        otp.expires_at = timezone.now() - timedelta(seconds=1)
        otp.save()

        data = {"user_id": str(self.user.id), "otp_code": otp.code}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data["success"])  # type: ignore

    def test_verify_otp_used_code(self):
        """Test OTP verification with already used code."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")
        otp.mark_as_used()

        data = {"user_id": str(self.user.id), "otp_code": otp.code}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data["success"])  # type: ignore

    def test_verify_otp_missing_fields(self):
        """Test OTP verification with missing required fields."""
        # Missing user_id
        response = self.client.post(self.url, {"otp_code": "123456"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Missing otp_code
        response = self.client.post(
            self.url, {"user_id": str(self.user.id)}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_otp_invalid_code_format(self):
        """Test OTP verification with invalid code format."""
        data = {"user_id": str(self.user.id), "otp_code": "abc123"}  # Contains letters

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_otp_wrong_length(self):
        """Test OTP verification with wrong code length."""
        # Too short
        data = {"user_id": str(self.user.id), "otp_code": "12345"}

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Too long
        data["otp_code"] = "1234567"
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_otp_token_validity(self):
        """Test that generated tokens are valid."""
        otp = OTP.objects.create(user=self.user, delivery_method="email")

        data = {"user_id": str(self.user.id), "otp_code": otp.code}

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test that the access token works
        access_token = response.data["access_token"]  # type: ignore
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")  # type: ignore

        # Try to access a protected endpoint
        profile_url = reverse("users:user-profile")
        profile_response = self.client.get(profile_url)

        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)
        self.assertEqual(profile_response.data["email"], self.user.email)  # type: ignore


class OTPIntegrationTest(BaseOTPTestCase):
    """Integration tests for complete OTP flow."""

    def test_complete_otp_flow(self):
        """Test complete OTP generation and verification flow."""
        # Step 1: Generate OTP
        with patch("apps.users.otp_views.send_otp_email.delay") as mock_email_task:
            generate_data = {"user_id": str(self.user.id), "method": "email"}

            generate_url = reverse("users:generate-otp")
            generate_response = self.client.post(
                generate_url, generate_data, format="json"
            )

            self.assertEqual(generate_response.status_code, status.HTTP_200_OK)
            self.assertTrue(generate_response.data["success"])  # type: ignore
            mock_email_task.assert_called_once()

        # Step 2: Get the generated OTP from database
        otp = OTP.objects.get(user=self.user, delivery_method="email")

        # Step 3: Verify OTP
        verify_data = {"user_id": str(self.user.id), "otp_code": otp.code}

        verify_url = reverse("users:verify-otp")
        verify_response = self.client.post(verify_url, verify_data, format="json")

        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertTrue(verify_response.data["success"])  # type: ignore
        self.assertIn("access_token", verify_response.data)  # type: ignore

        # Step 4: Verify that OTP is now used
        otp.refresh_from_db()
        self.assertTrue(otp.is_used)

        # Step 5: Try to use the same OTP again (should fail)
        second_verify_response = self.client.post(
            verify_url, verify_data, format="json"
        )
        self.assertEqual(
            second_verify_response.status_code, status.HTTP_401_UNAUTHORIZED
        )
        self.assertFalse(second_verify_response.data["success"])  # type: ignore

    def test_multiple_otp_generation_invalidates_previous(self):
        """Test that generating new OTP invalidates previous ones."""
        with patch("apps.users.otp_views.send_otp_email.delay"):
            generate_data = {"user_id": str(self.user.id), "method": "email"}
            generate_url = reverse("users:generate-otp")

            # Generate first OTP
            self.client.post(generate_url, generate_data, format="json")
            first_otp = OTP.objects.get(user=self.user, delivery_method="email")

            # Generate second OTP
            self.client.post(generate_url, generate_data, format="json")

            # First OTP should be expired
            first_otp.refresh_from_db()
            self.assertTrue(first_otp.is_expired)

            # Second OTP should be valid
            second_otp = OTP.objects.filter(
                user=self.user, delivery_method="email", is_expired=False
            ).first()
            self.assertIsNotNone(second_otp)
            self.assertIsNotNone(second_otp)
            self.assertTrue(second_otp.is_valid)  # type: ignore
