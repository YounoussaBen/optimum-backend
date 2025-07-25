"""
OTP (One Time Password) Authentication API Views using Django REST Framework.
Implements SMS/Email OTP generation and verification with JWT token authentication.
"""

import logging

from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    GenerateOTPResponseSerializer,
    GenerateOTPSerializer,
    OTPErrorResponseSerializer,
    VerifyOTPResponseSerializer,
    VerifyOTPSerializer,
)
from .tasks import send_otp_email, send_otp_sms
from .utils import OTPService

User = get_user_model()
logger = logging.getLogger(__name__)


class GenerateOTPView(CreateAPIView):
    """
    API view to generate OTP codes for user authentication.
    Sends OTP via SMS or Email using Celery background tasks.
    Public endpoint - no authentication required.
    """

    serializer_class = GenerateOTPSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Generate OTP code",
        operation_description="Generate a 6-digit OTP code and send it via SMS or email. "
        "The OTP expires after 60 seconds and invalidates any previous OTPs for the user.",
        responses={
            200: GenerateOTPResponseSerializer,
            400: OTPErrorResponseSerializer,
            404: OTPErrorResponseSerializer,
            500: OTPErrorResponseSerializer,
        },
        tags=["Authentication & Authorization"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Generate and send OTP code."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        delivery_method = serializer.validated_data["method"]

        try:
            # Generate OTP using service
            success, otp_instance, message = OTPService.generate_otp(
                user_id=user_id, delivery_method=delivery_method
            )

            if not success:
                logger.warning(f"OTP generation failed for user {user_id}: {message}")
                return Response(
                    {"success": False, "message": message},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Send OTP via background task
            try:
                if delivery_method == "email":
                    if otp_instance is None:
                        raise ValueError("OTP instance is None")
                    send_otp_email.delay(
                        user_id=user_id,
                        email=otp_instance.user.email,
                        otp_code=otp_instance.code,
                    )
                elif delivery_method == "sms":
                    if otp_instance is None:
                        raise ValueError("OTP instance is None")
                    send_otp_sms.delay(
                        user_id=user_id,
                        phone_number=otp_instance.user.phone_number,
                        otp_code=otp_instance.code,
                    )

                logger.info(
                    f"OTP generated and sent via {delivery_method} for user {user_id}"
                )

                # Return success response with masked contact info
                if otp_instance is None:
                    raise ValueError("OTP instance is None")
                response_data = {
                    "success": True,
                    "message": "OTP sent successfully",
                    "contact": otp_instance.get_masked_contact(),
                    "expires_in": 60,
                }

                return Response(response_data, status=status.HTTP_200_OK)

            except Exception as e:
                logger.error(f"Failed to send OTP for user {user_id}: {str(e)}")
                return Response(
                    {
                        "success": False,
                        "message": "Failed to send OTP. Please try again.",
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except Exception as e:
            logger.error(
                f"Unexpected error generating OTP for user {user_id}: {str(e)}"
            )
            return Response(
                {
                    "success": False,
                    "message": "Internal server error. Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class VerifyOTPView(CreateAPIView):
    """
    API view to verify OTP codes and authenticate users.
    Returns JWT tokens on successful verification.
    Public endpoint - no authentication required.
    """

    serializer_class = VerifyOTPSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Verify OTP code",
        operation_description="Verify a 6-digit OTP code and authenticate the user. "
        "Returns JWT access and refresh tokens on successful verification. "
        "The OTP can only be used once and expires after 60 seconds.",
        responses={
            200: VerifyOTPResponseSerializer,
            400: OTPErrorResponseSerializer,
            401: OTPErrorResponseSerializer,
            404: OTPErrorResponseSerializer,
            500: OTPErrorResponseSerializer,
        },
        tags=["Authentication & Authorization"],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Verify OTP code and authenticate user."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        otp_code = serializer.validated_data["otp_code"]

        try:
            # Verify OTP using service
            success, user_instance, message = OTPService.verify_otp(
                user_id=user_id, otp_code=otp_code
            )

            if not success:
                logger.warning(f"OTP verification failed for user {user_id}: {message}")

                # Determine appropriate status code
                status_code: int
                if "not found" in message.lower():
                    status_code = status.HTTP_404_NOT_FOUND
                elif "invalid" in message.lower() or "expired" in message.lower():
                    status_code = status.HTTP_401_UNAUTHORIZED
                else:
                    status_code = status.HTTP_400_BAD_REQUEST

                return Response(
                    {"success": False, "message": message}, status=status_code
                )

            # Authentication successful - generate JWT tokens
            if user_instance is None:
                raise ValueError("User instance is None")
            refresh = RefreshToken.for_user(user_instance)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            logger.info(f"OTP verification successful for user {user_id}")

            # Return success response with tokens and user info
            response_data = {
                "success": True,
                "message": "Authentication successful",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": {
                    "id": str(user_instance.id),
                    "name": user_instance.get_full_name(),
                    "email": user_instance.email,
                    "phone": user_instance.phone_number,
                },
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error verifying OTP for user {user_id}: {str(e)}")
            return Response(
                {
                    "success": False,
                    "message": "Internal server error. Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
