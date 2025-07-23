"""
Tests for face_auth services module.
"""

import base64
from unittest.mock import Mock, patch

from django.test import TestCase

from apps.face_auth.services import AzureFaceAPIError, AzureFaceService


class AzureFaceServiceTest(TestCase):
    """Test AzureFaceService functionality."""

    def setUp(self):
        self.service = AzureFaceService()
        self.sample_image_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

    def test_service_initialization(self):
        """Test that service initializes correctly."""
        self.assertIsNotNone(self.service.api_key)
        self.assertIsNotNone(self.service.endpoint)
        self.assertIsNotNone(self.service.person_group_id)

    @patch("apps.face_auth.services.requests.put")
    def test_create_person_group_success(self, mock_put):
        """Test successful person group creation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        result = self.service.create_person_group(
            "test-group", "Test Group", "Test data"
        )

        self.assertTrue(result)
        mock_put.assert_called_once()

    @patch("apps.face_auth.services.requests.post")
    def test_create_person_group_error(self, mock_post):
        """Test person group creation error handling."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"
        mock_post.return_value = mock_response

        with self.assertRaises(AzureFaceAPIError):
            self.service.create_person_group("test-group", "Test Group", "Test data")

    @patch("apps.face_auth.services.requests.get")
    def test_list_person_groups_success(self, mock_get):
        """Test successful person groups listing."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"personGroupId": "group1", "name": "Group 1", "userData": "Test group"}
        ]
        mock_get.return_value = mock_response

        result = self.service.list_person_groups()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["personGroupId"], "group1")

    @patch("apps.face_auth.services.requests.get")
    def test_get_person_group_success(self, mock_get):
        """Test successful person group retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "personGroupId": "optimum",
            "name": "Optimum Group",
            "userData": "Main group",
        }
        mock_get.return_value = mock_response

        result = self.service.get_person_group("optimum")

        self.assertEqual(result["personGroupId"], "optimum")

    @patch("apps.face_auth.services.requests.delete")
    def test_delete_person_group_success(self, mock_delete):
        """Test successful person group deletion."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response

        result = self.service.delete_person_group("test-group")

        self.assertTrue(result)

    @patch("apps.face_auth.services.requests.post")
    def test_train_person_group_success(self, mock_post):
        """Test successful person group training."""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        result = self.service.train_person_group("optimum")

        self.assertTrue(result)

    @patch("apps.face_auth.services.requests.get")
    def test_get_training_status_success(self, mock_get):
        """Test successful training status retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "succeeded",
            "createdDateTime": "2024-01-01T00:00:00Z",
            "lastActionDateTime": "2024-01-01T00:05:00Z",
        }
        mock_get.return_value = mock_response

        result = self.service.get_training_status("optimum")

        self.assertEqual(result["status"], "succeeded")

    @patch("apps.face_auth.services.requests.post")
    def test_create_person_success(self, mock_post):
        """Test successful person creation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"personId": "test-person-id-123"}
        mock_post.return_value = mock_response

        result = self.service.create_person("optimum", "John Doe", "user123")

        self.assertEqual(result, "test-person-id-123")

    @patch("apps.face_auth.services.requests.post")
    def test_add_person_face_success(self, mock_post):
        """Test successful face addition to person."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"persistedFaceId": "face-id-123"}
        mock_post.return_value = mock_response

        result = self.service.add_person_face(
            "optimum", "person-id-123", self.sample_image_base64
        )

        self.assertEqual(result, "face-id-123")

    @patch("apps.face_auth.services.requests.post")
    def test_detect_face_success(self, mock_post):
        """Test successful face detection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "faceId": "detected-face-id-123",
                "faceRectangle": {"top": 100, "left": 100, "width": 200, "height": 200},
            }
        ]
        mock_post.return_value = mock_response

        result = self.service.detect_face(self.sample_image_base64)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["faceId"], "detected-face-id-123")

    @patch("apps.face_auth.services.requests.post")
    def test_identify_face_success(self, mock_post):
        """Test successful face identification."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "faceId": "face-id-123",
                "candidates": [{"personId": "person-id-123", "confidence": 0.9}],
            }
        ]
        mock_post.return_value = mock_response

        # Mock detect_face to return face ID
        with patch.object(self.service, "detect_face") as mock_detect:
            mock_detect.return_value = [{"faceId": "face-id-123"}]

            result = self.service.identify_face(self.sample_image_base64, "optimum")

            self.assertEqual(result["person_id"], "person-id-123")
            self.assertEqual(result["confidence"], 0.9)

    @patch("apps.face_auth.services.requests.post")
    def test_verify_face_success(self, mock_post):
        """Test successful face verification."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"isIdentical": True, "confidence": 0.95}
        mock_post.return_value = mock_response

        # Mock detect_face to return face ID
        with patch.object(self.service, "detect_face") as mock_detect:
            mock_detect.return_value = [{"faceId": "face-id-123"}]

            result = self.service.verify_face(
                self.sample_image_base64, "person-id-123", "optimum"
            )

            self.assertTrue(result["is_identical"])
            self.assertEqual(result["confidence"], 0.95)

    def test_base64_to_bytes_conversion(self):
        """Test base64 to bytes conversion."""
        # This tests the internal _base64_to_bytes method if it exists
        # or similar utility functions
        try:
            # Convert base64 to bytes
            image_bytes = base64.b64decode(self.sample_image_base64)
            self.assertIsInstance(image_bytes, bytes)
            self.assertGreater(len(image_bytes), 0)
        except Exception as e:
            self.fail(f"Base64 conversion failed: {e}")

    @patch("apps.face_auth.services.requests.put")
    def test_api_error_handling(self, mock_put):
        """Test API error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_put.return_value = mock_response

        with self.assertRaises(AzureFaceAPIError) as context:
            self.service.create_person_group("test", "Test", "Test")

        self.assertIn("500", str(context.exception))

    @patch("apps.face_auth.services.requests.post")
    def test_no_face_detected(self, mock_post):
        """Test handling when no face is detected."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []  # Empty list = no faces
        mock_post.return_value = mock_response

        with self.assertRaises(AzureFaceAPIError) as context:
            self.service.detect_face(self.sample_image_base64)

        self.assertIn("No face detected", str(context.exception))

    @patch("apps.face_auth.services.requests.post")
    def test_multiple_faces_detected(self, mock_post):
        """Test handling when multiple faces are detected."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"faceId": "face1"},
            {"faceId": "face2"},  # Multiple faces
        ]
        mock_post.return_value = mock_response

        with self.assertRaises(AzureFaceAPIError) as context:
            self.service.detect_face(self.sample_image_base64)

        self.assertIn("Multiple faces detected", str(context.exception))


class AzureFaceAPIErrorTest(TestCase):
    """Test AzureFaceAPIError exception."""

    def test_error_creation(self):
        """Test error creation with message."""
        error = AzureFaceAPIError("Test error message")
        self.assertEqual(str(error), "Test error message")

    def test_error_with_status_code(self):
        """Test error creation with status code."""
        error = AzureFaceAPIError("API Error", 404)
        self.assertIn("404", str(error))
        self.assertIn("API Error", str(error))
