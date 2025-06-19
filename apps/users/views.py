from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from rest_framework.generics import (
    CreateAPIView,
    DestroyAPIView,
    ListAPIView,
    RetrieveAPIView,
    UpdateAPIView,
)
from rest_framework.permissions import IsAuthenticated

from .permissions import IsAdminUser
from .serializers import (
    UserCreateSerializer,
    UserDetailSerializer,
    UserListSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
)

User = get_user_model()


class UserListView(ListAPIView):
    """
    API view to list all users.
    Only accessible by admin users.
    """

    queryset = User.objects.all().order_by("-date_joined")
    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    search_fields = ["email", "first_name", "last_name", "phone_number"]
    filterset_fields = ["is_active", "is_verified", "face_added"]
    ordering_fields = ["date_joined", "email", "first_name", "last_name"]

    @swagger_auto_schema(
        operation_summary="List all users",
        operation_description="Retrieve a list of all users. Admin access required.",
        tags=["Admin - User Management"],
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
        tags=["Admin - User Management"],
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
        tags=["Admin - User Management"],
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
        tags=["Admin - User Management"],
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Partially update user",
        operation_description="Partially update user information. Admin access required.",
        tags=["Admin - User Management"],
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


class UserDeleteView(DestroyAPIView):
    """
    API view to delete users.
    Only accessible by admin users.
    """

    queryset = User.objects.all()
    permission_classes = [IsAuthenticated, IsAdminUser]
    lookup_field = "id"

    @swagger_auto_schema(
        operation_summary="Delete user",
        operation_description="Delete a user account. Admin access required.",
        tags=["Admin - User Management"],
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)

    def perform_destroy(self, instance):
        """
        Custom delete logic - you might want to add cleanup here
        (e.g., remove from Azure Face API, soft delete, etc.)
        """
        # TODO: Add Azure Face API cleanup when face_auth app is ready
        instance.delete()


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
        tags=["User Profile"],
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
    Only accessible by admin users.
    """

    serializer_class = UserDetailSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    lookup_field = "unique_pin_identifier"
    lookup_url_kwarg = "pin"

    @swagger_auto_schema(
        operation_summary="Get user by PIN",
        operation_description="Retrieve user information using PIN identifier. Admin access required.",
        tags=["Admin - User Management"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return User.objects.all()
