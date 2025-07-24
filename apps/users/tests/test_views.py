"""
Comprehensive tests for users app views.
"""

import uuid

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class BaseUserTestCase(TestCase):
    """Base test case with common setup for user tests."""

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

        # Create regular user
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
            first_name="Regular",
            last_name="User",
            phone_number="+1234567891",
            nationality="Test",
            gender="F",
        )
        self.regular_user.is_verified = True
        self.regular_user.save()

        # Create unverified user
        self.unverified_user = User.objects.create_user(
            email="unverified@test.com",
            password="testpass123",
            first_name="Unverified",
            last_name="User",
            phone_number="+1234567892",
            nationality="Test",
            gender="M",
        )

    def get_admin_token(self):
        """Get JWT token for admin user."""
        refresh = RefreshToken.for_user(self.admin_user)
        return str(refresh.access_token)

    def get_user_token(self):
        """Get JWT token for regular user."""
        refresh = RefreshToken.for_user(self.regular_user)
        return str(refresh.access_token)


class UserListViewTest(BaseUserTestCase):
    """Test UserListView - admin only endpoint."""

    def test_admin_can_list_users(self):
        """Admin users can list all users."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)

    def test_regular_user_cannot_list_users(self):
        """Regular users cannot access user list."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_cannot_list_users(self):
        """Unauthenticated users cannot access user list."""
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_search_users_by_email(self):
        """Admin can search users by email."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-list")
        response = self.client.get(url, {"search": "user@test.com"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["email"], "user@test.com")


class UserCreateViewTest(BaseUserTestCase):
    """Test UserCreateView - admin only endpoint."""

    def test_admin_can_create_user(self):
        """Admin can create new users."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-create")
        data = {
            "email": "newuser@test.com",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "+1234567893",
            "nationality": "Test",
            "gender": "M",
            "date_of_birth": "1990-01-01",
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email="newuser@test.com").exists())

    def test_create_user_with_duplicate_email(self):
        """Cannot create user with duplicate email."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-create")
        data = {
            "email": "user@test.com",  # Already exists
            "first_name": "Duplicate",
            "last_name": "User",
            "phone_number": "+1234567894",
            "nationality": "Test",
            "gender": "M",
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_with_invalid_phone(self):
        """Cannot create user with invalid phone number."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-create")
        data = {
            "email": "invalidphone@test.com",
            "first_name": "Invalid",
            "last_name": "Phone",
            "phone_number": "invalid-phone",
            "nationality": "Test",
            "gender": "M",
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserDetailViewTest(BaseUserTestCase):
    """Test UserDetailView - admin only endpoint."""

    def test_admin_can_view_user_detail(self):
        """Admin can view user details."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-detail", kwargs={"id": self.regular_user.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.regular_user.email)

    def test_user_detail_not_found(self):
        """404 for non-existent user."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-detail", kwargs={"id": uuid.uuid4()})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class UserUpdateViewTest(BaseUserTestCase):
    """Test UserUpdateView - admin only endpoint."""

    def test_admin_can_update_user(self):
        """Admin can update user details."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-update", kwargs={"id": self.regular_user.id})
        data = {"first_name": "Updated", "last_name": "Name"}
        response = self.client.patch(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.regular_user.refresh_from_db()
        self.assertEqual(self.regular_user.first_name, "Updated")


class UserDeleteViewTest(BaseUserTestCase):
    """Test UserDeleteView - admin only endpoint."""

    def test_admin_can_delete_user(self):
        """Admin can delete users."""
        user_to_delete = User.objects.create_user(
            email="delete@test.com",
            first_name="Delete",
            last_name="Me",
            phone_number="+1234567895",
            nationality="Test",
            gender="M",
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-delete", kwargs={"id": user_to_delete.id})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(id=user_to_delete.id).exists())


class UserByPinViewTest(BaseUserTestCase):
    """Test UserByPinView - utility endpoint."""

    def test_admin_can_find_user_by_pin(self):
        """Admin can find user by PIN."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse(
            "users:user-by-pin", kwargs={"pin": self.regular_user.unique_pin_identifier}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], str(self.regular_user.id))

    def test_user_by_pin_not_found(self):
        """404 for non-existent PIN."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:user-by-pin", kwargs={"pin": "999999999"})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class UserProfileViewTest(BaseUserTestCase):
    """Test UserProfileView - authenticated user's own profile."""

    def test_user_can_view_own_profile(self):
        """Authenticated user can view their own profile."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("users:user-profile")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.regular_user.email)


class DashboardStatsViewTest(BaseUserTestCase):
    """Test DashboardStatsView - admin dashboard."""

    def test_admin_can_view_dashboard_stats(self):
        """Admin can view dashboard statistics."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:dashboard-stats")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("stats", response.data)
        self.assertIn("total_users", response.data["stats"])
        self.assertIn("verified_users", response.data["stats"])


class AdminUserVerificationViewTest(BaseUserTestCase):
    """Test AdminUserVerificationView - admin can verify users."""

    def test_admin_can_verify_user(self):
        """Admin can verify unverified users."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:admin-verify-user")
        data = {"user_id": str(self.unverified_user.id), "verified": True}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.unverified_user.refresh_from_db()
        self.assertTrue(self.unverified_user.is_verified)

    def test_verify_nonexistent_user(self):
        """Cannot verify non-existent user."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:admin-verify-user")
        data = {"user_id": str(uuid.uuid4()), "verified": True}
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AdaptiveLearningStatsViewTest(BaseUserTestCase):
    """Test AdaptiveLearningStatsView - admin can view learning stats."""

    def test_admin_can_view_learning_stats(self):
        """Admin can view adaptive learning statistics."""
        # Create some auth attempts for testing
        self.regular_user.auth_faces_count = 5
        self.regular_user.face_added = True
        self.regular_user.save()

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:adaptive-learning-stats")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("average_auth_faces", response.data)
        self.assertIn("total_adaptive_faces_added", response.data)


class BulkUserImportViewTest(BaseUserTestCase):
    """Test BulkUserImportView - admin bulk user creation from JSON/CSV."""

    def test_admin_can_import_users_json(self):
        """Admin can import users from JSON data."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        users_data = [
            {
                "email": "bulk1@test.com",
                "first_name": "Bulk",
                "last_name": "User1",
                "phone_number": "+1234567893",
                "nationality": "TestNation",
                "gender": "M",
            },
            {
                "email": "bulk2@test.com",
                "first_name": "Bulk",
                "last_name": "User2",
                "phone_number": "+1234567894",
                "nationality": "TestNation",
                "gender": "F",
            },
        ]

        data = {"users_data": users_data}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["success_count"], 2)
        self.assertEqual(response.data["error_count"], 0)
        self.assertEqual(response.data["total_processed"], 2)

        # Verify users were created
        self.assertTrue(User.objects.filter(email="bulk1@test.com").exists())
        self.assertTrue(User.objects.filter(email="bulk2@test.com").exists())

        # Verify auto-generated PIN
        user1 = User.objects.get(email="bulk1@test.com")
        self.assertIsNotNone(user1.unique_pin_identifier)
        self.assertEqual(len(user1.unique_pin_identifier), 8)

    def test_admin_can_import_users_csv(self):
        """Admin can import users from CSV file."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        # Create CSV content
        csv_content = """email,first_name,last_name,phone_number,nationality,gender
csv1@test.com,CSV,User1,+1234567895,TestNation,M
csv2@test.com,CSV,User2,+1234567896,TestNation,F"""

        csv_file = SimpleUploadedFile(
            "users.csv", csv_content.encode("utf-8"), content_type="text/csv"
        )

        data = {"csv_file": csv_file}
        response = self.client.post(url, data, format="multipart")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["success_count"], 2)
        self.assertEqual(response.data["error_count"], 0)

        # Verify users were created
        self.assertTrue(User.objects.filter(email="csv1@test.com").exists())
        self.assertTrue(User.objects.filter(email="csv2@test.com").exists())

    def test_import_handles_validation_errors(self):
        """Import properly handles validation errors."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        users_data = [
            {
                "email": "valid@test.com",
                "first_name": "Valid",
                "last_name": "User",
                "phone_number": "+1234567897",
                "nationality": "TestNation",
                "gender": "M",
            },
            {
                "email": "invalid-email",  # Invalid email
                "first_name": "Invalid",
                "last_name": "User",
                "phone_number": "+1234567898",
                "nationality": "TestNation",
                "gender": "X",  # Invalid gender choice
            },
            {
                # Missing required email field
                "first_name": "No",
                "last_name": "Email",
                "phone_number": "+1234567899",
            },
        ]

        data = {"users_data": users_data}
        response = self.client.post(url, data, format="json")

        self.assertEqual(
            response.status_code, status.HTTP_201_CREATED
        )  # Partial success
        self.assertEqual(response.data["success_count"], 1)
        self.assertEqual(response.data["error_count"], 2)
        self.assertEqual(response.data["total_processed"], 3)

        # Check error details
        self.assertEqual(len(response.data["errors"]), 2)

        # Verify only valid user was created
        self.assertTrue(User.objects.filter(email="valid@test.com").exists())
        self.assertFalse(User.objects.filter(email="invalid-email").exists())

    def test_import_handles_duplicate_emails(self):
        """Import handles duplicate email addresses."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        users_data = [
            {
                "email": self.regular_user.email,  # Existing user email
                "first_name": "Duplicate",
                "last_name": "Email",
                "phone_number": "+1234567800",
                "nationality": "TestNation",
                "gender": "M",
            }
        ]

        data = {"users_data": users_data}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["success_count"], 0)
        self.assertEqual(response.data["error_count"], 1)
        self.assertEqual(response.data["total_processed"], 1)
        self.assertEqual(len(response.data["errors"]), 1)
        self.assertIn("email", response.data["errors"][0]["errors"])

    def test_regular_user_cannot_import(self):
        """Regular users cannot access bulk import."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_user_token()}")
        url = reverse("users:bulk-user-import")

        data = {"users_data": [{"email": "test@test.com"}]}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_cannot_import(self):
        """Unauthenticated users cannot access bulk import."""
        url = reverse("users:bulk-user-import")

        data = {"users_data": [{"email": "test@test.com"}]}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_import_requires_data_or_file(self):
        """Import requires either JSON data or CSV file."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        # Empty request
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_import_rejects_both_data_and_file(self):
        """Import rejects both JSON data and CSV file in same request."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        csv_file = SimpleUploadedFile(
            "test.csv", b"email\ntest@test.com", content_type="text/csv"
        )
        data = {"users_data": [{"email": "test@test.com"}], "csv_file": csv_file}

        response = self.client.post(url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_csv_with_invalid_encoding(self):
        """CSV import handles invalid file encoding."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.get_admin_token()}")
        url = reverse("users:bulk-user-import")

        # Create file with invalid UTF-8 content
        invalid_csv = SimpleUploadedFile(
            "invalid.csv",
            b"\xff\xfe\x00\x00",  # Invalid UTF-8 bytes
            content_type="text/csv",
        )

        data = {"csv_file": invalid_csv}
        response = self.client.post(url, data, format="multipart")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("CSV parsing error", str(response.data))
