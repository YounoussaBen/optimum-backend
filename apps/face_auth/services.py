"""
Azure Face API Service Layer
Handles all interactions with Azure Face API endpoints.
"""

import logging
from typing import Any

import requests
from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException, ErrorDetail, ValidationError

logger = logging.getLogger(__name__)


class AzureFaceAPIError(APIException):
    """Custom exception for Azure Face API errors."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Azure Face API service temporarily unavailable."
    default_code = "azure_face_api_error"

    def __init__(self, detail=None, status_code=None):
        super().__init__(detail)
        if status_code:
            self.status_code = status_code
            self.detail = ErrorDetail(
                f"{detail} (Status: {status_code})", code=self.default_code
            )


class AzureFaceService:
    """
    Service class for Azure Face API operations.
    Follows single responsibility principle - only handles Azure API calls.
    """

    def __init__(self):
        self.api_key = settings.AZURE_FACE_API_KEY
        self.endpoint = settings.AZURE_FACE_ENDPOINT.rstrip("/")
        self.default_person_group_id = settings.AZURE_FACE_PERSON_GROUP_ID
        self.person_group_id = self.default_person_group_id

        if not self.api_key:
            raise ValidationError("Azure Face API key not configured")
        if not self.endpoint:
            raise ValidationError("Azure Face API endpoint not configured")

    def _get_headers(self) -> dict[str, str]:
        """Get common headers for Azure Face API requests."""
        return {
            "Ocp-Apim-Subscription-Key": self.api_key,
            "Content-Type": "application/json",
        }

    def _handle_response(self, response: requests.Response, operation: str) -> Any:
        """
        Handle Azure Face API response and error cases.

        Args:
            response: requests.Response object
            operation: Description of the operation for logging

        Returns:
            Parsed JSON response or raises appropriate exception
        """
        logger.info(f"Azure Face API {operation}: Status {response.status_code}")

        try:
            response_data = response.json() if response.content else {}
        except ValueError:
            response_data = {}

        if response.status_code == 200:
            return response_data
        elif response.status_code == 202:
            # Accepted - for async operations like training
            return response_data
        elif response.status_code == 400:
            error_msg = self._extract_error_message(response_data)
            logger.warning(f"Azure Face API bad request for {operation}: {error_msg}")
            raise AzureFaceAPIError(f"Invalid request: {error_msg}", 400)
        elif response.status_code == 401:
            logger.error(f"Azure Face API unauthorized for {operation}")
            raise AzureFaceAPIError("Invalid API credentials")
        elif response.status_code == 403:
            logger.error(f"Azure Face API forbidden for {operation}")
            raise AzureFaceAPIError("API access forbidden")
        elif response.status_code == 404:
            logger.warning(f"Azure Face API resource not found for {operation}")
            raise ValidationError("Resource not found")
        elif response.status_code == 409:
            error_msg = self._extract_error_message(response_data)
            logger.warning(f"Azure Face API conflict for {operation}: {error_msg}")
            raise AzureFaceAPIError(f"Resource conflict: {error_msg}", 409)
        elif response.status_code == 429:
            logger.warning(f"Azure Face API rate limit exceeded for {operation}")
            raise AzureFaceAPIError("Rate limit exceeded. Please try again later.")
        else:
            logger.error(
                f"Azure Face API error for {operation}: {response.status_code}"
            )
            raise AzureFaceAPIError(
                f"API error: {response.status_code}", response.status_code
            )

    def _extract_error_message(self, response_data: dict) -> str:
        """Extract error message from Azure Face API response."""
        if isinstance(response_data, dict):
            if "error" in response_data:
                error = response_data["error"]
                if isinstance(error, dict):
                    return error.get("message", "Unknown error")
                return str(error)
            return response_data.get("message", "Unknown error")
        return "Unknown error"

    # Person Group Operations

    def create_person_group(
        self,
        person_group_id: str | None = None,
        name: str | None = None,
        user_data: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a person group in Azure Face API.

        Args:
            person_group_id: Custom person group ID or uses default
            name: Human-readable name for the person group
            user_data: Optional user data string

        Returns:
            Dict with creation result and person_group_id
        """
        group_id = person_group_id or self.default_person_group_id
        group_name = name or f"Person Group {group_id}"

        url = f"{self.endpoint}/persongroups/{group_id}"
        data = {
            "name": group_name,
            "userData": user_data or f"Created for app: {group_id}",
        }

        try:
            response = requests.put(
                url, headers=self._get_headers(), json=data, timeout=30
            )
            self._handle_response(response, f"create_person_group({group_id})")

            logger.info(f"Successfully created person group: {group_id}")
            return {
                "person_group_id": group_id,
                "name": group_name,
                "user_data": data["userData"],
                "created": True,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error creating person group {group_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def get_person_group(self, person_group_id: str | None = None) -> dict[str, Any]:
        """
        Get person group information.

        Args:
            person_group_id: Person group ID to retrieve

        Returns:
            Person group information
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}"

        try:
            response = requests.get(url, headers=self._get_headers(), timeout=30)
            result = self._handle_response(response, f"get_person_group({group_id})")

            logger.info(f"Successfully retrieved person group: {group_id}")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error getting person group {group_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def list_person_groups(self) -> list[dict[str, Any]]:
        """
        List all person groups.

        Returns:
            List of person groups
        """
        url = f"{self.endpoint}/persongroups"

        try:
            response = requests.get(url, headers=self._get_headers(), timeout=30)
            result = self._handle_response(response, "list_person_groups")

            logger.info(f"Successfully listed person groups: {len(result)} found")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error listing person groups: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def delete_person_group(self, person_group_id: str | None = None) -> dict[str, Any]:
        """
        Delete a person group.

        Args:
            person_group_id: Person group ID to delete

        Returns:
            Delete operation result
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}"

        try:
            response = requests.delete(url, headers=self._get_headers(), timeout=30)
            self._handle_response(response, f"delete_person_group({group_id})")

            logger.info(f"Successfully deleted person group: {group_id}")
            return {"person_group_id": group_id, "deleted": True}

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error deleting person group {group_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def train_person_group(self, person_group_id: str | None = None) -> dict[str, Any]:
        """
        Train a person group.

        Args:
            person_group_id: Person group ID to train

        Returns:
            Training status information
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}/train"

        try:
            response = requests.post(url, headers=self._get_headers(), timeout=30)
            self._handle_response(response, f"train_person_group({group_id})")

            logger.info(f"Successfully started training for person group: {group_id}")
            return {"person_group_id": group_id, "training_started": True}

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error training person group {group_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def get_training_status(self, person_group_id: str | None = None) -> dict[str, Any]:
        """
        Get training status of a person group.

        Args:
            person_group_id: Person group ID to check

        Returns:
            Training status information
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}/training"

        try:
            response = requests.get(url, headers=self._get_headers(), timeout=30)
            result = self._handle_response(response, f"get_training_status({group_id})")

            logger.info(f"Retrieved training status for person group: {group_id}")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error getting training status {group_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    # Person Operations

    def create_person(
        self,
        person_group_id: str,
        name: str,
        user_data: str | None = None,
    ) -> str:
        """
        Create a person in a person group.

        Args:
            person_group_id: Person group to add person to
            name: Person's name
            user_data: Optional user data

        Returns:
            Person ID string
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}/persons"

        data = {"name": name, "userData": user_data or ""}

        try:
            response = requests.post(
                url, headers=self._get_headers(), json=data, timeout=30
            )
            result = self._handle_response(
                response, f"create_person({name} in {group_id})"
            )

            person_id = result.get("personId")
            logger.info(f"Successfully created person {name} with ID: {person_id}")
            return person_id

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error creating person {name}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    # Face Operations

    def detect_face(self, image_base64: str) -> list[dict[str, Any]]:
        """
        Detect faces in an image.

        Args:
            image_base64: Base64 encoded image data

        Returns:
            List of detected faces with face IDs
        """
        url = f"{self.endpoint}/detect"
        params = {"returnFaceId": "true"}

        headers = self._get_headers()
        headers["Content-Type"] = "application/octet-stream"

        try:
            import base64

            image_data = base64.b64decode(image_base64)
            response = requests.post(
                url, headers=headers, data=image_data, params=params, timeout=30
            )

            result = self._handle_response(response, "detect_face")

            if len(result) == 0:
                raise AzureFaceAPIError("No face detected in the image")
            elif len(result) > 1:
                raise AzureFaceAPIError("Multiple faces detected in the image")

            logger.info(f"Successfully detected {len(result)} faces")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error detecting faces: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def verify_face(
        self, image_base64: str, person_id: str, person_group_id: str
    ) -> dict[str, Any]:
        """
        Verify if a face belongs to a specific person.

        Args:
            image_base64: Base64 encoded image data
            person_id: Person ID to verify against
            person_group_id: Person group containing the person

        Returns:
            Verification result with confidence score
        """
        # First detect face to get face ID
        faces = self.detect_face(image_base64)
        if not faces:
            raise AzureFaceAPIError("No face detected")

        face_id = faces[0]["faceId"]

        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/verify"

        data = {"faceId": face_id, "personGroupId": group_id, "personId": person_id}

        try:
            response = requests.post(
                url, headers=self._get_headers(), json=data, timeout=30
            )
            result = self._handle_response(
                response, f"verify_face({face_id} vs {person_id})"
            )

            # Convert response format to match test expectations
            formatted_result = {
                "is_identical": result.get("isIdentical", False),
                "confidence": result.get("confidence", 0.0),
            }

            logger.info(
                f"Face verification result: {formatted_result['is_identical']} "
                f"(confidence: {formatted_result['confidence']:.3f})"
            )
            return formatted_result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error verifying face: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def identify_face(self, image_base64: str, person_group_id: str) -> dict[str, Any]:
        """
        Identify a face in a person group.

        Args:
            image_base64: Base64 encoded image data
            person_group_id: Person group to search in

        Returns:
            Identification result with person_id and confidence
        """
        # First detect face to get face ID
        faces = self.detect_face(image_base64)
        if not faces:
            raise AzureFaceAPIError("No face detected")

        face_id = faces[0]["faceId"]

        url = f"{self.endpoint}/identify"
        data = {
            "faceIds": [face_id],
            "personGroupId": person_group_id,
            "maxNumOfCandidatesReturned": 1,
            "confidenceThreshold": 0.5,
        }

        try:
            response = requests.post(
                url, headers=self._get_headers(), json=data, timeout=30
            )
            result = self._handle_response(
                response, f"identify_face in {person_group_id}"
            )

            if not result or not result[0].get("candidates"):
                raise AzureFaceAPIError("No matching person found")

            candidate = result[0]["candidates"][0]
            formatted_result = {
                "person_id": candidate["personId"],
                "confidence": candidate["confidence"],
            }

            logger.info(
                f"Face identification result: {formatted_result['person_id']} "
                f"(confidence: {formatted_result['confidence']:.3f})"
            )
            return formatted_result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error identifying face: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def delete_person(
        self, person_id: str, person_group_id: str | None = None
    ) -> dict[str, Any]:
        """
        Delete a person from a person group.
        This removes the person and all their associated faces.

        Args:
            person_id: Person ID to delete
            person_group_id: Person group containing the person

        Returns:
            Delete operation result
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}/persons/{person_id}"

        try:
            response = requests.delete(url, headers=self._get_headers(), timeout=30)
            self._handle_response(response, f"delete_person({person_id})")

            logger.info(
                f"Successfully deleted person {person_id} from group {group_id}"
            )
            return {
                "person_id": person_id,
                "person_group_id": group_id,
                "deleted": True,
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error deleting person {person_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None

    def add_person_face(
        self,
        person_group_id: str,
        person_id: str,
        image_base64: str,
        user_data: str | None = None,
    ) -> str:
        """
        Add a face to a person in a person group.

        Args:
            person_group_id: Person group containing the person
            person_id: Person ID to add face to
            image_base64: Base64 encoded image data
            user_data: Optional user data for the face

        Returns:
            Persisted face ID string
        """
        group_id = person_group_id or self.default_person_group_id
        url = f"{self.endpoint}/persongroups/{group_id}/persons/{person_id}/persistedFaces"

        headers = self._get_headers()
        headers["Content-Type"] = "application/octet-stream"

        params = {}
        if user_data:
            params["userData"] = user_data

        try:
            import base64

            image_data = base64.b64decode(image_base64)
            response = requests.post(
                url, headers=headers, data=image_data, params=params, timeout=30
            )

            result = self._handle_response(response, f"add_person_face({person_id})")

            face_id = result.get("persistedFaceId")
            logger.info(f"Successfully added face to person {person_id}: {face_id}")
            return face_id

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error adding face to person {person_id}: {str(e)}")
            raise AzureFaceAPIError(
                "Network error connecting to Azure Face API"
            ) from None
