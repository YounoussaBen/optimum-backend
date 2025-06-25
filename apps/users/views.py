import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, cast

from django.contrib.auth import get_user_model
from django.db.models import Avg, Sum
from django.utils import timezone
from drf_yasg import openapi
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
from rest_framework.views import APIView

from .permissions import IsAdminUser
from .serializers import (
    DashboardDataSerializer,
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


class AdminUserVerificationView(CreateAPIView):
    """
    API view for admin to verify/unverify users.
    Sets proper expiration timers for verified users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Verify or unverify user",
        operation_description="Admin endpoint to verify/unverify a user. "
        "Verified users get a expiration timer and must complete monthly verification.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "user_id": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="UUID of the user to verify/unverify",
                ),
                "verified": openapi.Schema(
                    type=openapi.TYPE_BOOLEAN,
                    description="True to verify user, False to unverify",
                ),
            },
            required=["user_id", "verified"],
        ),
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "success": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    "message": openapi.Schema(type=openapi.TYPE_STRING),
                    "user_id": openapi.Schema(type=openapi.TYPE_STRING),
                    "is_verified": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    "verification_expires_at": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        format=openapi.FORMAT_DATETIME,
                        nullable=True,
                    ),
                },
            ),
            400: "Bad Request - Invalid user ID or data",
            404: "Not Found - User not found",
            401: "Unauthorized - Admin access required",
        },
        tags=["User Management"],
    )
    def post(self, request, *args, **kwargs):
        """Verify or unverify a user with proper expiration handling."""

        user_id = request.data.get("user_id")
        verified = request.data.get("verified")

        if user_id is None or verified is None:
            return Response(
                {"success": False, "error": "user_id and verified fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"success": False, "error": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if verified:
            # Verify user with proper expiration timer
            expiration_time = user.set_verified_with_expiration(verified_by_admin=True)

            logger.info(
                f"Admin {request.user.email} verified user {user.id}. "
                f"Expires at: {expiration_time}"
            )

            message = f"User {user.get_full_name()} verified successfully. Must complete self-verification."

        else:
            # Unverify user
            user.expire_verification()

            logger.info(f"Admin {request.user.email} unverified user {user.id}")

            message = f"User {user.get_full_name()} verification removed."

        return Response(
            {
                "success": True,
                "message": message,
                "user_id": str(user.id),
                "is_verified": user.is_verified,
                "verification_expires_at": (
                    user.verification_expires_at.isoformat()
                    if user.verification_expires_at
                    else None
                ),
            },
            status=status.HTTP_200_OK,
        )


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


class DashboardStatsView(APIView):
    """
    API view to get dashboard statistics and data.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Get dashboard statistics",
        operation_description="Retrieve dashboard statistics including user counts, verification data, and recent activities. Admin access required.",
        responses={
            200: DashboardDataSerializer,
            401: "Unauthorized - Admin access required",
        },
        tags=["Dashboard"],
    )
    def get(self, request, *args, **kwargs):
        """Get complete dashboard data."""
        dashboard_data = {
            "stats": self._get_dashboard_stats(),
            "verification_chart": self._get_verification_chart_data(),
            "recent_activities": self._get_recent_activities(),
        }

        serializer = DashboardDataSerializer(dashboard_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _get_dashboard_stats(self) -> dict[str, Any]:
        """Calculate dashboard statistics from real data."""
        now = timezone.now()
        current_month_start = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        last_month_start = (current_month_start - timedelta(days=1)).replace(day=1)

        # Get current stats (non-staff users only)
        current_total = User.objects.filter(is_staff=False, is_superuser=False).count()
        current_verified = User.objects.filter(
            is_staff=False, is_superuser=False, is_verified=True, is_active=True
        ).count()

        # Failed verifications = users who are overdue for verification
        current_failed = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            is_active=True,
            verification_expires_at__lt=now,
            is_verified=False,
        ).count()

        current_active_faces = User.objects.filter(
            is_staff=False, is_superuser=False, face_added=True
        ).count()

        # Get last month stats for percentage calculation
        last_month_total = User.objects.filter(
            is_staff=False, is_superuser=False, date_joined__lt=current_month_start
        ).count()

        last_month_verified = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            is_verified=True,
            is_active=True,
            date_joined__lt=current_month_start,
        ).count()

        last_month_failed = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            is_active=True,
            verification_expires_at__range=[last_month_start, current_month_start],
            is_verified=False,
        ).count()

        last_month_faces = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            face_added=True,
            date_joined__lt=current_month_start,
        ).count()

        def calculate_change(current: int, previous: int) -> float:
            if previous == 0:
                return 100.0 if current > 0 else 0.0
            return ((current - previous) / previous) * 100

        return {
            "total_users": current_total,
            "verified_users": current_verified,
            "failed_verifications": current_failed,
            "active_faces": current_active_faces,
            "total_users_change": calculate_change(current_total, last_month_total),
            "verified_users_change": calculate_change(
                current_verified, last_month_verified
            ),
            "failed_verifications_change": calculate_change(
                current_failed, last_month_failed
            ),
            "active_faces_change": calculate_change(
                current_active_faces, last_month_faces
            ),
        }

    def _get_verification_chart_data(self) -> list[Any]:
        """
        Get verification chart data for the last 30 days.
        Returns empty array since we don't have VerificationAttempt model yet.
        TODO: Implement real verification tracking.
        """
        return []

    def _get_recent_activities(self) -> list[dict[str, Any]]:
        """Get real recent activities based on actual user actions."""
        activities: list[dict[str, Any]] = []

        recent_users = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            date_joined__gte=timezone.now() - timedelta(days=7),
        ).order_by("-date_joined")[:5]

        for user in recent_users:
            activities.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "user_created",
                    "message": f"New user {user.get_full_name()} was registered in the system",
                    "timestamp": user.date_joined,
                    "user_id": str(user.id),
                    "admin_id": None,
                }
            )

        recently_verified = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            is_verified=True,
            updated_at__gte=timezone.now() - timedelta(days=7),
        ).order_by("-updated_at")[:3]

        for user in recently_verified:
            activities.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "user_verified",
                    "message": f"{user.get_full_name()} completed verification successfully",
                    "timestamp": user.updated_at,
                    "user_id": str(user.id),
                    "admin_id": None,
                }
            )

        recent_faces = User.objects.filter(
            is_staff=False,
            is_superuser=False,
            face_added=True,
            updated_at__gte=timezone.now() - timedelta(days=7),
        ).order_by("-updated_at")[:2]

        for user in recent_faces:
            activities.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "face_added",
                    "message": f"Face data added for {user.get_full_name()}",
                    "timestamp": user.updated_at,
                    "user_id": str(user.id),
                    "admin_id": None,
                }
            )

        activities.sort(
            key=lambda x: cast(datetime, x.get("timestamp") or timezone.now()),
            reverse=True,
        )
        return activities[:10]


class AdaptiveLearningStatsView(APIView):
    """
    API view to get adaptive learning statistics.
    Only accessible by admin users.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Get adaptive learning statistics",
        operation_description="Retrieve statistics about the adaptive face learning system. Admin access required.",
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "total_users_with_faces": openapi.Schema(type=openapi.TYPE_INTEGER),
                    "users_still_learning": openapi.Schema(type=openapi.TYPE_INTEGER),
                    "users_at_max_capacity": openapi.Schema(type=openapi.TYPE_INTEGER),
                    "users_never_authenticated": openapi.Schema(
                        type=openapi.TYPE_INTEGER
                    ),
                    "average_auth_faces": openapi.Schema(type=openapi.TYPE_NUMBER),
                    "total_adaptive_faces_added": openapi.Schema(
                        type=openapi.TYPE_INTEGER
                    ),
                    "distribution": openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "range": openapi.Schema(type=openapi.TYPE_STRING),
                                "count": openapi.Schema(type=openapi.TYPE_INTEGER),
                                "percentage": openapi.Schema(type=openapi.TYPE_NUMBER),
                            },
                        ),
                    ),
                    "recent_learners": openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "user_id": openapi.Schema(type=openapi.TYPE_STRING),
                                "name": openapi.Schema(type=openapi.TYPE_STRING),
                                "auth_faces_count": openapi.Schema(
                                    type=openapi.TYPE_INTEGER
                                ),
                                "last_updated": openapi.Schema(
                                    type=openapi.TYPE_STRING
                                ),
                            },
                        ),
                    ),
                },
            ),
            401: "Unauthorized - Admin access required",
        },
        tags=["Dashboard"],
    )
    def get(self, request, *args, **kwargs):
        """Get comprehensive adaptive learning statistics."""
        try:
            # Get all active users with face registration
            users = User.objects.filter(
                is_active=True, face_added=True, person_id__isnull=False
            ).exclude(person_id="")

            total_users = users.count()

            if total_users == 0:
                return Response(
                    {
                        "message": "No users with face registration found",
                        "total_users_with_faces": 0,
                        "users_still_learning": 0,
                        "users_at_max_capacity": 0,
                        "users_never_authenticated": 0,
                        "average_auth_faces": 0,
                        "total_adaptive_faces_added": 0,
                        "distribution": [],
                        "recent_learners": [],
                    }
                )

            # Calculate statistics
            stats = users.aggregate(
                avg_auth_faces=Avg("auth_faces_count"),
                total_adaptive_faces=Sum("auth_faces_count"),
            )

            # Count users by categories
            learning_active = users.filter(auth_faces_count__lt=100).count()
            learning_maxed = users.filter(auth_faces_count=100).count()
            never_authenticated = users.filter(auth_faces_count=0).count()

            # Calculate distribution
            ranges = [
                (0, 0, "Never authenticated"),
                (1, 10, "1-10 authentications"),
                (11, 25, "11-25 authentications"),
                (26, 50, "26-50 authentications"),
                (51, 75, "51-75 authentications"),
                (76, 99, "76-99 authentications"),
                (100, 100, "Maximum (100 authentications)"),
            ]

            distribution = []
            for min_count, max_count, label in ranges:
                count = users.filter(
                    auth_faces_count__gte=min_count, auth_faces_count__lte=max_count
                ).count()
                percentage = (count / total_users) * 100 if total_users > 0 else 0
                distribution.append(
                    {"range": label, "count": count, "percentage": round(percentage, 1)}
                )

            # Get recent learners (users who have added faces recently)
            recent_learners = users.filter(auth_faces_count__gt=0).order_by(
                "-updated_at"
            )[:10]

            recent_learners_data = []
            for user in recent_learners:
                recent_learners_data.append(
                    {
                        "user_id": str(user.id),
                        "name": user.get_full_name(),
                        "auth_faces_count": user.auth_faces_count,
                        "last_updated": user.updated_at.isoformat(),
                    }
                )

            response_data = {
                "total_users_with_faces": total_users,
                "users_still_learning": learning_active,
                "users_at_max_capacity": learning_maxed,
                "users_never_authenticated": never_authenticated,
                "average_auth_faces": round(stats["avg_auth_faces"] or 0, 2),
                "total_adaptive_faces_added": stats["total_adaptive_faces"] or 0,
                "distribution": distribution,
                "recent_learners": recent_learners_data,
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting adaptive learning stats: {str(e)}")
            return Response(
                {"error": "Failed to retrieve adaptive learning statistics"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
