"""
Comprehensive tests for face_auth app views.
"""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.face_auth.services import AzureFaceAPIError

User = get_user_model()


class BaseFaceAuthTestCase(TestCase):
    """Base test case with common setup for face auth tests."""

    def setUp(self):
        self.client: APIClient = APIClient()

        # Create admin user
        self.admin_user = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            phone_number="+1234567890",
            nationality="Test",
            gender="M",
        )

        # Create regular user with face registered
        self.user_with_face = User.objects.create_user(
            email="faceuser@test.com",
            password="testpass123",
            first_name="Face",
            last_name="User",
            phone_number="+1234567891",
            nationality="Test",
            gender="F",
        )
        self.user_with_face.is_verified = True
        self.user_with_face.face_added = True
        self.user_with_face.person_id = "test-person-id-123"
        self.user_with_face.save()

        # Create user without face
        self.user_no_face = User.objects.create_user(
            email="noface@test.com",
            password="testpass123",
            first_name="No",
            last_name="Face",
            phone_number="+1234567892",
            nationality="Test",
            gender="M",
        )
        self.user_no_face.is_verified = True
        self.user_no_face.save()

        # Sample base64 image data (minimal valid base64)
        self.sample_image_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

    def get_admin_token(self):
        """Get JWT token for admin user."""
        refresh = RefreshToken.for_user(self.admin_user)
        return str(refresh.access_token)

    def get_user_token(self):
        """Get JWT token for regular user."""
        refresh = RefreshToken.for_user(self.user_with_face)
        return str(refresh.access_token)


class FaceAuthenticationViewTest(BaseFaceAuthTestCase):
    """Test FaceAuthenticationView - public face login endpoint."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_successful_face_authentication(self, mock_service):
        """Successful face authentication returns JWT tokens."""
        # Mock successful face identification
        mock_service_instance = mock_service.return_value
        mock_service_instance.identify_face.return_value = {
            "person_id": self.user_with_face.person_id,
            "confidence": 0.9,
        }

        url = reverse("face_auth:face-login")
        data = {
            "pin": self.user_with_face.unique_pin_identifier,
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        # Removed debug output
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.data)
        self.assertIn("refresh_token", response.data)
        self.assertEqual(response.data["user"]["email"], self.user_with_face.email)

    @patch("apps.face_auth.views.AzureFaceService")
    def test_face_authentication_wrong_person(self, mock_service):
        """Face authentication with wrong person ID fails."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.identify_face.return_value = {
            "person_id": "different-person-id",
            "confidence": 0.9,
        }

        url = reverse("face_auth:face-login")
        data = {
            "pin": self.user_with_face.unique_pin_identifier,
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("apps.face_auth.views.AzureFaceService")
    def test_face_authentication_low_confidence(self, mock_service):
        """Face authentication with low confidence fails."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.identify_face.return_value = {
            "person_id": self.user_with_face.person_id,
            "confidence": 0.3,  # Low confidence
        }

        url = reverse("face_auth:face-login")
        data = {
            "pin": self.user_with_face.unique_pin_identifier,
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_face_authentication_invalid_pin(self):
        """Face authentication with invalid PIN fails."""
        url = reverse("face_auth:face-login")
        data = {
            "pin": "999999999",  # Non-existent PIN
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_face_authentication_user_no_face(self):
        """Face authentication for user without face fails."""
        url = reverse("face_auth:face-login")
        data = {
            "pin": self.user_no_face.unique_pin_identifier,
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("apps.face_auth.views.AzureFaceService")
    def test_face_authentication_api_error(self, mock_service):
        """Face authentication handles Azure API errors."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.identify_face.side_effect = AzureFaceAPIError("API Error")

        url = reverse("face_auth:face-login")
        data = {
            "pin": self.user_with_face.unique_pin_identifier,
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class FaceVerificationViewTest(BaseFaceAuthTestCase):
    """Test FaceVerificationView - authenticated user face verification."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_successful_face_verification(self, mock_service):
        """Successful face verification for authenticated user."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.verify_face.return_value = {
            "is_identical": True,
            "confidence": 0.9,
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("face_auth:face-verify")
        data = {"image_data": self.sample_image_base64}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["verified"])

    @patch("apps.face_auth.views.AzureFaceService")
    def test_face_verification_fails(self, mock_service):
        """Face verification fails for non-matching face."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.verify_face.return_value = {
            "is_identical": False,
            "confidence": 0.3,
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("face_auth:face-verify")
        data = {"image_data": self.sample_image_base64}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["verified"])

    def test_face_verification_unauthenticated(self):
        """Face verification requires authentication."""
        url = reverse("face_auth:face-verify")
        data = {"image_data": self.sample_image_base64}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PersonGroupCreateViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupCreateView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_create_person_group(self, mock_service):
        """Admin can create new person groups."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.create_person_group.return_value = {
            "person_group_id": "test-group",
            "name": "Test Group",
            "user_data": "Test group for testing",
            "created": True,
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-create")
        data = {
            "person_group_id": "test-group",
            "name": "Test Group",
            "user_data": "Test group for testing",
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        mock_service_instance.create_person_group.assert_called_once()

    def test_non_admin_cannot_create_person_group(self):
        """Non-admin users cannot create person groups."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("face_auth:person-group-create")
        data = {"person_group_id": "test-group", "name": "Test Group"}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class PersonGroupListViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupListView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_list_person_groups(self, mock_service):
        """Admin can list person groups."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.list_person_groups.return_value = [
            {"personGroupId": "group1", "name": "Group 1", "userData": "Test group 1"}
        ]

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["person_groups"]), 1)


class PersonGroupInfoViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupInfoView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_get_person_group_info(self, mock_service):
        """Admin can get person group information."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.get_person_group.return_value = {
            "personGroupId": "optimum",
            "name": "Optimum Group",
            "userData": "Main group",
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-info")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["personGroupId"], "optimum")


class PersonGroupDeleteViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupDeleteView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_delete_person_group(self, mock_service):
        """Admin can delete person groups."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.delete_person_group.return_value = True

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-delete")
        data = {"person_group_id": "test-group"}
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


class PersonGroupTrainViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupTrainView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_train_person_group(self, mock_service):
        """Admin can trigger person group training."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.train_person_group.return_value = {
            "person_group_id": "optimum",
            "training_started": True,
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-train")
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)


class PersonGroupTrainingStatusViewTest(BaseFaceAuthTestCase):
    """Test PersonGroupTrainingStatusView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_get_training_status(self, mock_service):
        """Admin can get person group training status."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.get_training_status.return_value = {
            "status": "succeeded",
            "created_time": "2024-01-01T00:00:00Z",
            "last_action_time": "2024-01-01T00:05:00Z",
        }

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:person-group-training-status")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "succeeded")


class AddUserToPersonGroupViewTest(BaseFaceAuthTestCase):
    """Test AddUserToPersonGroupView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_add_user_to_person_group(self, mock_service):
        """Admin can add user to person group."""
        mock_service_instance = mock_service.return_value
        mock_service_instance.create_person.return_value = "new-person-id-123"

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:user-add-to-group")
        data = {"user_id": str(self.user_no_face.id), "person_group_id": "optimum"}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.user_no_face.refresh_from_db()
        self.assertEqual(self.user_no_face.person_id, "new-person-id-123")

    def test_add_nonexistent_user_to_person_group(self):
        """Cannot add non-existent user to person group."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:user-add-to-group")
        data = {"user_id": str(uuid.uuid4()), "person_group_id": "optimum"}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AddUserFaceViewTest(BaseFaceAuthTestCase):
    """Test AddUserFaceView - admin only."""

    @patch("apps.face_auth.views.AzureFaceService")
    def test_admin_can_add_user_face(self, mock_service):
        """Admin can add face to user."""
        # First give user a person_id
        self.user_no_face.person_id = "test-person-id"
        self.user_no_face.save()

        mock_service_instance = mock_service.return_value
        mock_service_instance.add_person_face.return_value = "face-id-123"

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:user-add-face")
        data = {
            "user_id": str(self.user_no_face.id),
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.user_no_face.refresh_from_db()
        self.assertTrue(self.user_no_face.face_added)

    def test_add_face_to_user_without_person_id(self):
        """Cannot add face to user without person_id."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:user-add-face")
        data = {
            "user_id": str(self.user_no_face.id),
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("apps.face_auth.views.AzureFaceService")
    def test_add_face_api_error(self, mock_service):
        """Handle Azure API errors when adding face."""
        self.user_no_face.person_id = "test-person-id"
        self.user_no_face.save()

        mock_service_instance = mock_service.return_value
        mock_service_instance.add_person_face.side_effect = AzureFaceAPIError(
            "API Error"
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("face_auth:user-add-face")
        data = {
            "user_id": str(self.user_no_face.id),
            "image_data": self.sample_image_base64,
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
