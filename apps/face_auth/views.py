# apps/face_auth/views.py
"""
Face Authentication API Views using Django REST Framework Generic Views.
Implements Azure Face API integration with proper error handling and logging.
"""

import base64
import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import (
    CreateAPIView,
    DestroyAPIView,
    ListAPIView,
    RetrieveAPIView,
)
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    AddUserFaceResponseSerializer,
    AddUserFaceSerializer,
    AddUserToPersonGroupResponseSerializer,
    AddUserToPersonGroupSerializer,
    FaceAuthenticationResponseSerializer,
    FaceAuthenticationSerializer,
    FaceVerificationResponseSerializer,
    FaceVerificationSerializer,
    PersonGroupCreateSerializer,
    PersonGroupInfoSerializer,
    PersonGroupListSerializer,
    PersonGroupResponseSerializer,
    TrainingStatusSerializer,
)
from .services import AzureFaceAPIError, AzureFaceService

User = get_user_model()
logger = logging.getLogger(__name__)


class PersonGroupCreateView(CreateAPIView):
    """
    API view to create Azure Face API person groups.
    Only accessible by admin users.
    """

    serializer_class = PersonGroupCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Create person group",
        operation_description="Create a new person group in Azure Face API. ",
        responses={
            201: PersonGroupResponseSerializer,
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Admin access required",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Create person group using Azure Face API."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            azure_service = AzureFaceService()
            result = azure_service.create_person_group(
                person_group_id=serializer.validated_data.get("person_group_id"),
                name=serializer.validated_data.get("name"),
                user_data=f"Created via API by {request.user.email}",
            )

            logger.info(
                f"Person group created by admin {request.user.email}: "
                f"{result['person_group_id']}"
            )

            response_data = {
                "person_group_id": result["person_group_id"],
                "name": result["name"],
                "created": True,
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error in person group creation: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error in person group creation: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PersonGroupListView(ListAPIView):
    """
    API view to list all person groups.
    Only accessible by admin users.
    """

    serializer_class = PersonGroupListSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="List person groups",
        operation_description="List all person groups in Azure Face API.",
        responses={
            200: PersonGroupListSerializer(many=True),
            401: "Unauthorized - Admin access required",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def get(self, request, *args, **kwargs):
        """List all person groups."""
        try:
            azure_service = AzureFaceService()
            person_groups = azure_service.list_person_groups()

            logger.info(f"Person groups listed by admin {request.user.email}")

            serializer = PersonGroupListSerializer(data=person_groups, many=True)
            serializer.is_valid(raise_exception=True)

            return Response(serializer.data)

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error listing person groups: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error listing person groups: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PersonGroupInfoView(RetrieveAPIView):
    """
    API view to get person group information.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Get person group info",
        operation_description="Retrieve information about a person group. ",
        manual_parameters=[
            openapi.Parameter(
                "person_group_id",
                openapi.IN_QUERY,
                description="Person group ID to retrieve",
                type=openapi.TYPE_STRING,
                required=False,
            )
        ],
        responses={
            200: PersonGroupInfoSerializer,
            401: "Unauthorized - Admin access required",
            404: "Not Found - Person group does not exist",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def get(self, request, *args, **kwargs):
        """Get person group information."""
        person_group_id = request.query_params.get("person_group_id")

        try:
            azure_service = AzureFaceService()
            result = azure_service.get_person_group(person_group_id)

            logger.info(f"Person group info retrieved by admin {request.user.email}")

            # Return the raw result from Azure API
            return Response(result)

        except ValidationError as e:
            if "Resource not found" in str(e):
                return Response(
                    {"error": "Person group not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            raise e
        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error retrieving person group: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error retrieving person group: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PersonGroupDeleteView(DestroyAPIView):
    """
    API view to delete a person group.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Delete person group",
        operation_description="Delete a person group in Azure Face API.",
        manual_parameters=[
            openapi.Parameter(
                "person_group_id",
                openapi.IN_QUERY,
                description="Person group ID to delete",
                type=openapi.TYPE_STRING,
                required=False,
            )
        ],
        responses={
            204: "No Content - Person group deleted successfully",
            401: "Unauthorized - Admin access required",
            404: "Not Found - Person group does not exist",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def delete(self, request, *args, **kwargs):
        """Delete person group."""
        person_group_id = request.query_params.get("person_group_id")

        try:
            azure_service = AzureFaceService()
            azure_service.delete_person_group(person_group_id)

            logger.info(
                f"Person group deleted by admin {request.user.email}: {person_group_id}"
            )

            return Response(status=status.HTTP_204_NO_CONTENT)

        except ValidationError as e:
            if "Resource not found" in str(e):
                return Response(
                    {"error": "Person group not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            raise e
        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error deleting person group: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error deleting person group: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PersonGroupTrainView(CreateAPIView):
    """
    API view to train a person group.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Train person group",
        operation_description="Start training for a person group. ",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "person_group_id": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Optional person group ID"
                )
            },
        ),
        responses={
            202: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "person_group_id": openapi.Schema(type=openapi.TYPE_STRING),
                    "training_started": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    "message": openapi.Schema(type=openapi.TYPE_STRING),
                },
            ),
            401: "Unauthorized - Admin access required",
            404: "Not Found - Person group does not exist",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def post(self, request, *args, **kwargs):
        """Start training for a person group."""
        person_group_id = request.data.get("person_group_id")

        try:
            azure_service = AzureFaceService()
            result = azure_service.train_person_group(person_group_id)

            logger.info(
                f"Person group training started by admin {request.user.email}: "
                f"{result['person_group_id']}"
            )

            return Response(
                {
                    "person_group_id": result["person_group_id"],
                    "training_started": result["training_started"],
                    "message": "Training started successfully",
                },
                status=status.HTTP_202_ACCEPTED,
            )

        except ValidationError as e:
            if "Resource not found" in str(e):
                return Response(
                    {"error": "Person group not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            raise e
        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error training person group: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error training person group: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PersonGroupTrainingStatusView(RetrieveAPIView):
    """
    API view to get person group training status.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Get training status",
        operation_description="Get training status for a person group. ",
        manual_parameters=[
            openapi.Parameter(
                "person_group_id",
                openapi.IN_QUERY,
                description="Person group ID to check",
                type=openapi.TYPE_STRING,
                required=False,
            )
        ],
        responses={
            200: TrainingStatusSerializer,
            401: "Unauthorized - Admin access required",
            404: "Not Found - Person group does not exist",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Person Group Management"],
    )
    def get(self, request, *args, **kwargs):
        """Get person group training status."""
        person_group_id = request.query_params.get("person_group_id")

        try:
            azure_service = AzureFaceService()
            result = azure_service.get_training_status(person_group_id)

            logger.info(f"Training status retrieved by admin {request.user.email}")

            return Response(result)

        except ValidationError as e:
            if "Resource not found" in str(e):
                return Response(
                    {"error": "Person group not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            raise e
        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error getting training status: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error getting training status: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AddUserToPersonGroupView(CreateAPIView):
    """
    API view to add a User to a person group.
    This creates the person in Azure and updates the User's person_id.
    Only accessible by admin users.
    """

    serializer_class = AddUserToPersonGroupSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Add user to person group",
        operation_description="Add an existing User to a person group. "
        "This creates the person in Azure and updates the User's person_id.",
        responses={
            201: AddUserToPersonGroupResponseSerializer,
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Admin access required",
            404: "Not Found - User not found",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["User Management"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Add user to person group using Azure Face API."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        person_group_id = serializer.validated_data.get("person_group_id")

        try:
            # Get the user
            try:
                user = User.objects.get(id=user_id, is_active=True)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
                )

            # Check if user already has a person_id
            if user.person_id:
                return Response(
                    {
                        "error": "User already added to person group",
                        "user_id": user.id,
                        "person_id": user.person_id,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            azure_service = AzureFaceService()

            # Create person in Azure using user's full name
            result = azure_service.create_person(
                name=user.get_full_name(),
                person_group_id=person_group_id,
                user_data=f"User ID: {user.id}",
            )

            person_id = result.get("personId")

            if not person_id:
                logger.error("Azure Face API did not return a person ID")
                return Response(
                    {"error": "Failed to create person in Azure Face API"},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            # Update user with person_id
            user.person_id = person_id
            user.save(update_fields=["person_id"])

            logger.info(
                f"User {user.id} added to person group by admin {request.user.email}"
            )

            response_data = {
                "user_id": user.id,
                "person_id": person_id,
                "person_group_id": person_group_id
                or azure_service.default_person_group_id,
                "message": "User successfully added to person group",
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error adding user to person group: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error adding user to person group: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@method_decorator(never_cache, name="dispatch")
class FaceAuthenticationView(CreateAPIView):
    """
    API view for face-based authentication.
    Authenticates users using PIN + face verification.
    Public endpoint - no authentication required.
    """

    serializer_class = FaceAuthenticationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Face authentication",
        operation_description="Authenticate user using PIN and face verification. "
        "Returns JWT tokens on successful authentication.",
        responses={
            200: FaceAuthenticationResponseSerializer,
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Authentication failed",
            404: "Not Found - User not found",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Authentication & Verification"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Authenticate user with face + PIN."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        pin = serializer.validated_data["pin"]
        confidence_threshold = serializer.validated_data.get(
            "confidence_threshold", 0.7
        )
        person_group_id = serializer.validated_data.get(
            "person_group_id"
        )  # Add this line

        try:
            # Get user by PIN
            user = User.objects.get_by_pin(pin)
            if not user or not user.is_active:
                logger.warning(f"Authentication failed: Invalid PIN {pin}")
                return Response(
                    {"success": False, "message": "Invalid credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if user has face registered
            if not user.face_added or not user.person_id:
                logger.warning(
                    f"Authentication failed: No face registered for user {user.id}"
                )
                return Response(
                    {"success": False, "message": "Face not registered for this user"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Prepare image data
            image_data = self._prepare_image_data(serializer.validated_data)

            # Initialize Azure Face Service
            azure_service = AzureFaceService()

            # Detect face in submitted image
            detected_faces = azure_service.detect_face(
                image_url=image_data.get("image_url"),
                image_data=image_data.get("image_binary"),
            )

            if not detected_faces:
                logger.warning(
                    f"Authentication failed: No face detected for user {user.id}"
                )
                return Response(
                    {"success": False, "message": "No face detected in the image"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use the first detected face
            face_id = detected_faces[0]["faceId"]

            # Verify face against user's person in Azure (with optional person group)
            verification_result = azure_service.verify_face(
                face_id=face_id,
                person_id=user.person_id,
                person_group_id=person_group_id,  # Add this line
            )

            is_identical = verification_result.get("isIdentical", False)
            confidence = verification_result.get("confidence", 0.0)

            if is_identical and confidence >= confidence_threshold:
                # Authentication successful - generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                logger.info(
                    f"Successful face authentication for user {user.id} "
                    f"(confidence: {confidence:.3f})"
                )

                return Response(
                    {
                        "success": True,
                        "user_id": user.id,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "confidence_score": confidence,
                        "message": "Authentication successful",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.warning(
                    f"Authentication failed for user {user.id}: "
                    f"identical={is_identical}, confidence={confidence:.3f}"
                )
                return Response(
                    {
                        "success": False,
                        "confidence_score": confidence,
                        "message": "Face verification failed",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error during authentication: {str(e)}")
            return Response(
                {
                    "success": False,
                    "message": "Face verification service temporarily unavailable",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error during face authentication: {str(e)}")
            return Response(
                {"success": False, "message": "Authentication service error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _prepare_image_data(self, validated_data: dict) -> dict[str, Any]:
        """Prepare image data for Azure Face API call."""
        if validated_data.get("image_url"):
            return {"image_url": validated_data["image_url"]}
        elif validated_data.get("image_data"):
            # Convert base64 to binary
            image_binary = base64.b64decode(validated_data["image_data"])
            return {"image_binary": image_binary}
        elif validated_data.get("image_file"):
            # Read uploaded file
            image_file = validated_data["image_file"]
            image_binary = image_file.read()
            return {"image_binary": image_binary}
        else:
            raise ValidationError("No image data provided")


@method_decorator(never_cache, name="dispatch")
class FaceVerificationView(CreateAPIView):
    """
    API view for face verification during sensitive operations.
    Requires user to be authenticated and verifies their identity.
    """

    serializer_class = FaceVerificationSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Face verification",
        operation_description="Verify user's identity using face recognition for sensitive operations.",
        responses={
            200: FaceVerificationResponseSerializer,
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Verification failed",
            403: "Forbidden - Cannot verify other users",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["Authentication & Verification"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Verify user's face for sensitive operations."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Determine which user to verify
        target_user_id = serializer.validated_data.get("user_id")
        person_group_id = serializer.validated_data.get(
            "person_group_id"
        )  # Add this line
        confidence_threshold = serializer.validated_data.get(
            "confidence_threshold", 0.8
        )

        if target_user_id:
            # Only admin can verify other users
            if not request.user.is_staff:
                return Response(
                    {
                        "verified": False,
                        "message": "Permission denied: Cannot verify other users",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            try:
                target_user = User.objects.get(id=target_user_id, is_active=True)
            except User.DoesNotExist:
                return Response(
                    {"verified": False, "message": "Target user not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            target_user = request.user

        try:
            # Check if user has face registered
            if not target_user.face_added or not target_user.person_id:
                logger.warning(
                    f"Verification failed: No face registered for user {target_user.id}"
                )
                return Response(
                    {
                        "verified": False,
                        "user_id": target_user.id,
                        "message": "Face not registered for this user",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Prepare image data
            image_data = self._prepare_image_data(serializer.validated_data)

            # Initialize Azure Face Service
            azure_service = AzureFaceService()

            # Detect face in submitted image
            detected_faces = azure_service.detect_face(
                image_url=image_data.get("image_url"),
                image_data=image_data.get("image_binary"),
            )

            if not detected_faces:
                logger.warning(
                    f"Verification failed: No face detected for user {target_user.id}"
                )
                return Response(
                    {
                        "verified": False,
                        "user_id": target_user.id,
                        "message": "No face detected in the image",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use the first detected face
            face_id = detected_faces[0]["faceId"]

            # Verify face against user's person in Azure (with optional person group)
            verification_result = azure_service.verify_face(
                face_id=face_id,
                person_id=target_user.person_id,
                person_group_id=person_group_id,  # Add this line
            )

            is_identical = verification_result.get("isIdentical", False)
            confidence = verification_result.get("confidence", 0.0)

            if is_identical and confidence >= confidence_threshold:
                # Verification successful - update user verification status

                # Use the new verification method for consistency
                if not request.user.is_staff:  # Only for normal users, not admin
                    expiration_time = target_user.set_verified_with_expiration(
                        verified_by_admin=False
                    )

                    logger.info(
                        f"Face verification successful for user {target_user.id} "
                        f"(confidence: {confidence:.3f}, expires at: {expiration_time})"
                    )
                else:
                    # For admin users, still no expiration (they don't need monthly verification)
                    target_user.is_verified = True
                    target_user.verification_expires_at = None
                    target_user.save(
                        update_fields=["is_verified", "verification_expires_at"]
                    )

                    logger.info(
                        f"Face verification successful for admin user {target_user.id} "
                        f"(confidence: {confidence:.3f}, no expiration set)"
                    )

                return Response(
                    {
                        "verified": True,
                        "user_id": target_user.id,
                        "confidence_score": confidence,
                        "message": "Identity verified successfully",
                        "expires_at": (
                            target_user.verification_expires_at.isoformat()
                            if target_user.verification_expires_at
                            else None
                        ),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.warning(
                    f"Verification failed for user {target_user.id}: "
                    f"identical={is_identical}, confidence={confidence:.3f}"
                )
                return Response(
                    {
                        "verified": False,
                        "user_id": target_user.id,
                        "confidence_score": confidence,
                        "message": "Face verification failed",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error during verification: {str(e)}")
            return Response(
                {
                    "verified": False,
                    "user_id": target_user.id,
                    "message": "Face verification service temporarily unavailable",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error during face verification: {str(e)}")
            return Response(
                {
                    "verified": False,
                    "user_id": target_user.id,
                    "message": "Verification service error",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _prepare_image_data(self, validated_data: dict) -> dict[str, Any]:
        """Prepare image data for Azure Face API call."""
        if validated_data.get("image_url"):
            return {"image_url": validated_data["image_url"]}
        elif validated_data.get("image_data"):
            # Convert base64 to binary
            image_binary = base64.b64decode(validated_data["image_data"])
            return {"image_binary": image_binary}
        elif validated_data.get("image_file"):
            # Read uploaded file
            image_file = validated_data["image_file"]
            image_binary = image_file.read()
            return {"image_binary": image_binary}
        else:
            raise ValidationError("No image data provided")


class AddUserFaceView(CreateAPIView):
    """
    API view to add a face to a user.
    Only accessible by admin users.
    """

    serializer_class = AddUserFaceSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Add face to user",
        operation_description="Add a face image to a user. "
        "User must already be added to a person group.",
        responses={
            201: AddUserFaceResponseSerializer,
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Admin access required",
            404: "Not Found - User not found",
            503: "Service Unavailable - Azure Face API error",
        },
        tags=["User Management"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Add face to user using Azure Face API."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        person_group_id = serializer.validated_data.get("person_group_id")

        try:
            # Get the user
            try:
                user = User.objects.get(id=user_id, is_active=True)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
                )

            # Check if user has person_id
            if not user.person_id:
                return Response(
                    {
                        "error": "User not added to person group yet. Add user to person group first.",
                        "user_id": user.id,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Prepare image data
            image_data = self._prepare_image_data(serializer.validated_data)

            azure_service = AzureFaceService()
            result = azure_service.add_person_face(
                person_id=user.person_id,
                person_group_id=person_group_id,
                image_url=image_data.get("image_url"),
                image_data=image_data.get("image_binary"),
                user_data=f"Face for user {user.id}",
            )

            # Update user face_added status
            user.face_added = True
            user.save(update_fields=["face_added"])

            logger.info(f"Face added to user {user.id} by admin {request.user.email}")

            response_data = {
                "user_id": user.id,
                "persistedFaceId": result.get("persistedFaceId"),
                "message": "Face added successfully",
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        except AzureFaceAPIError as e:
            logger.error(f"Azure Face API error adding face: {str(e)}")
            return Response(
                {"error": "Face API service error", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f"Unexpected error adding face: {str(e)}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _prepare_image_data(self, validated_data: dict) -> dict[str, Any]:
        """Prepare image data for Azure Face API call."""
        if validated_data.get("image_url"):
            return {"image_url": validated_data["image_url"]}
        elif validated_data.get("image_data"):
            # Convert base64 to binary
            image_binary = base64.b64decode(validated_data["image_data"])
            return {"image_binary": image_binary}
        elif validated_data.get("image_file"):
            # Read uploaded file
            image_file = validated_data["image_file"]
            image_binary = image_file.read()
            return {"image_binary": image_binary}
        else:
            raise ValidationError("No image data provided")
