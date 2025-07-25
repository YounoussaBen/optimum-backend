# Add these imports at the top
import logging

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    AdminLoginResponseSerializer,
    AdminLoginSerializer,
    TokenRefreshResponseSerializer,
)

# Initialize logger
logger = logging.getLogger(__name__)

# Add these new views to apps/users/views.py


class AdminLoginView(CreateAPIView):
    """
    API view for admin email/password authentication.
    Only accessible by staff/superuser accounts.
    """

    serializer_class = AdminLoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Admin login",
        operation_description="Authenticate admin user with email and password. "
        "Only staff and superuser accounts can use this endpoint.",
        responses={
            200: AdminLoginResponseSerializer,
            400: "Bad Request - Invalid credentials",
            401: "Unauthorized - Access denied",
        },
        tags=["Authentication & Authorization"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Authenticate admin user and return JWT tokens."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        logger.info(f"Admin login successful for user {user.email}")

        response_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user,
        }

        return Response(
            AdminLoginResponseSerializer(response_data).data, status=status.HTTP_200_OK
        )


class AdminLogoutView(CreateAPIView):
    """
    API view for admin logout.
    Blacklists the refresh token to prevent reuse.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Admin logout",
        operation_description="Logout admin user and blacklist refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh_token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Refresh token to blacklist"
                )
            },
            required=["refresh_token"],
        ),
        responses={
            200: "Logout successful",
            400: "Bad Request - Invalid token",
            401: "Unauthorized - Admin access required",
        },
        tags=["Authentication & Authorization"],
    )
    def post(self, request, *args, **kwargs):
        """Logout admin user by blacklisting refresh token."""
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(f"Admin logout successful for user {request.user.email}")

            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken):
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class TokenRefreshView(CreateAPIView):
    """
    API view for refreshing JWT access tokens.
    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Refresh access token",
        operation_description="Get a new access token using refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh_token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Valid refresh token"
                )
            },
            required=["refresh_token"],
        ),
        responses={
            200: TokenRefreshResponseSerializer,
            400: "Bad Request - Invalid token",
            401: "Unauthorized - Token expired",
        },
        tags=["Authentication & Authorization"],
    )
    def post(self, request, *args, **kwargs):
        """Refresh access token using refresh token."""
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            return Response({"access_token": access_token}, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken):
            return Response(
                {"error": "Invalid or expired refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )
