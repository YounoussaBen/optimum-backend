import logging

from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.generics import (
    CreateAPIView,
    DestroyAPIView,
    ListAPIView,
    RetrieveAPIView,
    UpdateAPIView,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .permissions import IsAdminUser
from .serializers import (
    UserCreateSerializer,
    UserDetailSerializer,
    UserListSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
)

User = get_user_model()


User = get_user_model()
logger = logging.getLogger(__name__)


class UserListView(ListAPIView):
    """
    API view to list all users.
    Only accessible by admin users.
    Returns only non-staff and non-admin users.
    """

    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    search_fields = ["email", "first_name", "last_name", "phone_number"]
    filterset_fields = ["is_active", "is_verified", "face_added"]
    ordering_fields = ["date_joined", "email", "first_name", "last_name"]

    def get_queryset(self):
        return User.objects.filter(is_staff=False, is_superuser=False).order_by(
            "-date_joined"
        )

    @swagger_auto_schema(
        operation_summary="List all users",
        operation_description="Retrieve a list of all non-staff and non-admin users. Admin access required.",
        tags=["User Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserCreateView(CreateAPIView):
    """
    API view to create new users.
    Only accessible by admin users.
    """

    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Create new user",
        operation_description="Create a new user account. Admin access required.",
        tags=["User Management"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        """Save the new user with auto-generated PIN."""
        user = serializer.save()
        # The PIN is auto-generated in the model's save method
        return user


class UserDetailView(RetrieveAPIView):
    """
    API view to retrieve detailed user information.
    Only accessible by admin users.
    """

    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    lookup_field = "id"

    @swagger_auto_schema(
        operation_summary="Get user details",
        operation_description="Retrieve detailed information about a specific user. Admin access required.",
        tags=["User Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserUpdateView(UpdateAPIView):
    """
    API view to update user information.
    Only accessible by admin users.
    """

    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    lookup_field = "id"

    @swagger_auto_schema(
        operation_summary="Update user",
        operation_description="Update user information. Admin access required.",
        tags=["User Management"],
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Partially update user",
        operation_description="Partially update user information. Admin access required.",
        tags=["User Management"],
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


class UserDeleteView(DestroyAPIView):
    """
    API view to delete users.
    Only accessible by admin users.
    Includes Azure Face API cleanup.
    """

    queryset = User.objects.all()
    permission_classes = [IsAuthenticated, IsAdminUser]
    lookup_field = "id"

    @swagger_auto_schema(
        operation_summary="Delete user",
        operation_description="Delete a user account and clean up Azure Face API data. Admin access required.",
        responses={
            204: "User deleted successfully",
            400: "Bad Request - Validation errors",
            401: "Unauthorized - Admin access required",
            404: "Not Found - User not found",
            500: "Internal Server Error - Cleanup failed",
        },
        tags=["User Management"],
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)

    def perform_destroy(self, instance):
        """
        Custom delete logic with Azure Face API cleanup.
        Removes user from Azure person group before deleting from database.
        """
        user_id = instance.id
        person_id = instance.person_id

        # Log the deletion attempt
        admin_email = (
            self.request.user.email
            if self.request.user.is_authenticated
            else "anonymous"
        )
        logger.info(
            f"Deleting user {user_id} (email: {instance.email}) "
            f"by admin {admin_email}"
        )

        # Clean up Azure Face API data if user has person_id
        azure_cleanup_success = True
        if person_id:
            try:
                # Import here to avoid circular imports
                from apps.face_auth.services import AzureFaceAPIError, AzureFaceService

                azure_service = AzureFaceService()
                azure_service.delete_person(person_id)

                logger.info(
                    f"Successfully cleaned up Azure person {person_id} for user {user_id}"
                )

            except AzureFaceAPIError as e:
                azure_cleanup_success = False
                logger.error(f"Azure Face API error during user cleanup: {str(e)}")

                # Decision: Continue with deletion even if Azure cleanup fails
                # This prevents users from being "stuck" due to Azure API issues
                # Log the error but don't block the deletion
                logger.warning(
                    "Proceeding with user deletion despite Azure cleanup failure"
                )

            except Exception as e:
                azure_cleanup_success = False
                logger.error(f"Unexpected error during Azure cleanup: {str(e)}")
                logger.warning(
                    "Proceeding with user deletion despite Azure cleanup failure"
                )
        else:
            logger.info(
                f"No Azure person_id found for user {user_id}, skipping Azure cleanup"
            )

        # Delete the user from Django database
        try:
            instance.delete()
            logger.info(f"Successfully deleted user {user_id} from database")

            # Log cleanup status
            if person_id:
                if azure_cleanup_success:
                    logger.info(f"User {user_id} fully cleaned up (Django + Azure)")
                else:
                    logger.warning(
                        f"User {user_id} deleted from Django but Azure cleanup failed. "
                        f"Orphaned person_id: {person_id}"
                    )

        except Exception as e:
            logger.error(f"Failed to delete user {user_id} from database: {str(e)}")
            raise

    def destroy(self, request, *args, **kwargs):
        """
        Override destroy to provide custom response with cleanup status.
        """
        try:
            instance = self.get_object()
            person_id = instance.person_id

            # Perform the deletion with cleanup
            self.perform_destroy(instance)

            # Return success response
            response_data = {
                "message": "User deleted successfully",
                "azure_cleanup_performed": bool(person_id),
            }

            return Response(response_data, status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            logger.error(f"Error during user deletion: {str(e)}")
            return Response(
                {"error": "Failed to delete user", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserProfileView(RetrieveAPIView):
    """
    API view for users to view their own profile.
    Users can only see their own profile data.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get current user profile",
        operation_description="Retrieve the current authenticated user's profile information.",
        tags=["User Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        """Return the current authenticated user."""
        return self.request.user


class UserByPinView(RetrieveAPIView):
    """
    API view to retrieve user by PIN.
    Useful for face authentication flow.
    No authentication required.
    """

    serializer_class = UserDetailSerializer
    permission_classes = [AllowAny]
    lookup_field = "unique_pin_identifier"
    lookup_url_kwarg = "pin"

    @swagger_auto_schema(
        operation_summary="Get user by PIN",
        operation_description="Retrieve user information using PIN identifier. No authentication required.",
        tags=["User Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return User.objects.all()
