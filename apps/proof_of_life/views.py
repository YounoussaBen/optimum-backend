from datetime import timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    ProofOfLifeAuditLog,
    ProofOfLifePendingVerification,
    ProofOfLifeSettings,
    ProofOfLifeVerification,
)
from .serializers import (
    ProofOfLifeErrorResponseSerializer,
    ProofOfLifeHistoryResponseSerializer,
    ProofOfLifeStatusResponseSerializer,
    ProofOfLifeVerificationModelSerializer,
    ProofOfLifeVerificationRequestSerializer,
    ProofOfLifeVerificationResponseSerializer,
)

User = get_user_model()


class ProofOfLifeStatusView(APIView):
    """
    Get current proof of life status for a user.

    Returns the user's current verification status, next due date,
    and other relevant information for the app to determine
    whether to show reminders or block actions.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get user verification status",
        operation_description="Get proof of life status for user",
        tags=["Proof of Life"],
        responses={
            200: ProofOfLifeStatusResponseSerializer,
            404: ProofOfLifeErrorResponseSerializer,
        },
    )
    def get(self, request):
        """Get proof of life status for authenticated user."""
        user = request.user

        # Get user's most recent verification
        latest_verification = (
            ProofOfLifeVerification.objects.filter(user=user)
            .order_by("-verification_date")
            .first()
        )

        # Get settings for grace period calculation
        settings = ProofOfLifeSettings.get_settings()

        if not latest_verification:
            # User has never verified - give them grace period to start
            next_due_date = timezone.now() + timedelta(days=settings.grace_period_days)
            response_data = {
                "success": True,
                "message": "Welcome! Please complete your first verification within the grace period",
                "status": "due_soon",
                "next_due_date": next_due_date,
                "last_verification_date": None,
                "days_until_due": settings.grace_period_days,
                "is_overdue": False,
                "grace_period_days": settings.grace_period_days,
            }
        else:
            # Update status based on current date
            latest_verification.update_status()

            response_data = {
                "success": True,
                "message": "Status retrieved successfully",
                "status": latest_verification.status,
                "next_due_date": latest_verification.next_due_date,
                "last_verification_date": latest_verification.verification_date,
                "days_until_due": latest_verification.days_until_due,
                "is_overdue": latest_verification.is_overdue,
                "grace_period_days": settings.grace_period_days,
            }

        return Response(response_data, status=status.HTTP_200_OK)


class ProofOfLifeVerificationView(APIView):
    """
    Submit face recognition for proof of life verification (Step 1).

    This endpoint validates scores and creates a pending verification
    that requires OTP confirmation to complete.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Submit face verification (Step 1)",
        operation_description="Submit face recognition for proof of life verification (Step 1 of 2)",
        tags=["Proof of Life"],
        request_body=ProofOfLifeVerificationRequestSerializer,
        responses={
            200: openapi.Response(
                description="Face verification successful - OTP required to complete",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "success": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "session_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "requires_otp": openapi.Schema(
                            type=openapi.TYPE_BOOLEAN, default=True
                        ),
                        "face_verification_successful": openapi.Schema(
                            type=openapi.TYPE_BOOLEAN
                        ),
                        "confidence_score": openapi.Schema(type=openapi.TYPE_NUMBER),
                        "liveness_score": openapi.Schema(type=openapi.TYPE_NUMBER),
                    },
                ),
            ),
            400: ProofOfLifeErrorResponseSerializer,
            404: ProofOfLifeErrorResponseSerializer,
            409: ProofOfLifeErrorResponseSerializer,
        },
    )
    def post(self, request):
        """Submit face recognition for proof of life verification."""
        user = request.user

        # Validate request data
        serializer = ProofOfLifeVerificationRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "message": "Invalid request data",
                    "error_code": "INVALID_REQUEST",
                    "errors": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        validated_data = serializer.validated_data

        # Get current settings
        settings = ProofOfLifeSettings.get_settings()

        # Extract scores and device info
        confidence_score = validated_data["confidence_score"]
        liveness_score = validated_data["liveness_score"]
        device_info = validated_data["device_info"]
        verification_timestamp = timezone.now()  # Use current server time

        # Get client IP and user agent for audit logging
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Log verification attempt
        ProofOfLifeAuditLog.log_verification_attempt(
            user=user,
            confidence_score=confidence_score,
            liveness_score=liveness_score,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Check if user already verified this month
        thirty_days_ago = timezone.now() - timedelta(days=30)
        recent_verification = ProofOfLifeVerification.objects.filter(
            user=user, verification_date__gte=thirty_days_ago
        ).first()

        if recent_verification:
            ProofOfLifeAuditLog.log_verification_failure(
                user=user,
                reason="Already verified this month",
                metadata={
                    "last_verification": recent_verification.verification_date.isoformat()
                },
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return Response(
                {
                    "success": False,
                    "message": "Already verified this month",
                    "error_code": "ALREADY_VERIFIED",
                },
                status=status.HTTP_409_CONFLICT,
            )

        # Validate minimum scores
        confidence_met = confidence_score >= settings.minimum_confidence_score
        liveness_met = liveness_score >= settings.minimum_liveness_score
        face_verification_successful = confidence_met and liveness_met

        if not face_verification_successful:
            reasons = []
            if not confidence_met:
                reasons.append(
                    f"Confidence score {confidence_score} below minimum {settings.minimum_confidence_score}"
                )
            if not liveness_met:
                reasons.append(
                    f"Liveness score {liveness_score} below minimum {settings.minimum_liveness_score}"
                )

            failure_reason = "; ".join(reasons)

            ProofOfLifeAuditLog.log_verification_failure(
                user=user,
                reason=failure_reason,
                metadata={
                    "confidence_score": float(confidence_score),
                    "liveness_score": float(liveness_score),
                    "minimum_confidence": float(settings.minimum_confidence_score),
                    "minimum_liveness": float(settings.minimum_liveness_score),
                },
                ip_address=ip_address,
                user_agent=user_agent,
            )

            return Response(
                {
                    "success": False,
                    "message": "Face verification failed - scores below minimum requirements",
                    "error_code": "INSUFFICIENT_SCORES",
                    "face_verification_successful": False,
                    "minimum_confidence_met": confidence_met,
                    "minimum_liveness_met": liveness_met,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Clear any existing pending verifications for this user
        ProofOfLifePendingVerification.objects.filter(user=user).delete()

        # Create pending verification record
        pending_verification = ProofOfLifePendingVerification.objects.create(
            user=user,
            confidence_score=confidence_score,
            liveness_score=liveness_score,
            face_verification_timestamp=verification_timestamp,
            device_id=device_info["device_id"],
            device_platform=device_info["platform"],
            app_version=device_info["app_version"],
            os_version=device_info["os_version"],
        )

        response_data = {
            "success": True,
            "message": "Face verification successful - OTP confirmation required to complete proof of life",
            "session_token": pending_verification.session_token,
            "requires_otp": True,
            "face_verification_successful": True,
            "confidence_score": float(confidence_score),
            "liveness_score": float(liveness_score),
        }

        return Response(response_data, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class ProofOfLifeOTPGenerateView(APIView):
    """
    Generate OTP for proof of life verification (Step 2A).

    This endpoint generates and sends an OTP to complete the proof of life
    verification process after successful face recognition.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Generate OTP (Step 2A)",
        operation_description="Generate OTP for proof of life verification completion",
        tags=["Proof of Life"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "session_token": openapi.Schema(type=openapi.TYPE_STRING),
                "method": openapi.Schema(
                    type=openapi.TYPE_STRING, enum=["email", "sms"]
                ),
            },
            required=["session_token", "method"],
        ),
        responses={
            200: openapi.Response(
                description="OTP sent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "success": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "contact": openapi.Schema(type=openapi.TYPE_STRING),
                        "expires_in": openapi.Schema(type=openapi.TYPE_INTEGER),
                    },
                ),
            ),
            400: ProofOfLifeErrorResponseSerializer,
            404: ProofOfLifeErrorResponseSerializer,
        },
    )
    def post(self, request):
        """Generate OTP for proof of life verification."""
        session_token = request.data.get("session_token")
        method = request.data.get("method")

        if not session_token or not method:
            return Response(
                {
                    "success": False,
                    "message": "Session token and method are required",
                    "error_code": "MISSING_PARAMETERS",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if method not in ["email", "sms"]:
            return Response(
                {
                    "success": False,
                    "message": "Method must be email or sms",
                    "error_code": "INVALID_METHOD",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            pending_verification = ProofOfLifePendingVerification.objects.get(
                session_token=session_token
            )
        except ProofOfLifePendingVerification.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "message": "Invalid or expired session token",
                    "error_code": "INVALID_SESSION_TOKEN",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Check if session has expired
        if pending_verification.is_expired:
            pending_verification.delete()
            return Response(
                {
                    "success": False,
                    "message": "Verification session has expired. Please start over.",
                    "error_code": "SESSION_EXPIRED",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Use the existing OTP service to generate and send OTP
        from apps.users.tasks import send_otp_email, send_otp_sms
        from apps.users.utils import OTPService

        try:
            success, otp_instance, message = OTPService.generate_otp(
                user_id=str(pending_verification.user.id), delivery_method=method
            )

            if not success or not otp_instance:
                return Response(
                    {
                        "success": False,
                        "message": message,
                        "error_code": "OTP_GENERATION_FAILED",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Send OTP via background task
            if method == "email":
                send_otp_email.delay(
                    user_id=str(pending_verification.user.id),
                    email=pending_verification.user.email,
                    otp_code=otp_instance.code,
                )
            else:  # sms
                send_otp_sms.delay(
                    user_id=str(pending_verification.user.id),
                    phone_number=pending_verification.user.phone_number,
                    otp_code=otp_instance.code,
                )

            # Mark OTP as sent for this pending verification
            pending_verification.mark_otp_sent(method)

            return Response(
                {
                    "success": True,
                    "message": "OTP sent successfully for proof of life verification",
                    "contact": otp_instance.get_masked_contact(),
                    "expires_in": 60,
                },
                status=status.HTTP_200_OK,
            )

        except Exception:
            return Response(
                {
                    "success": False,
                    "message": "Failed to send OTP. Please try again.",
                    "error_code": "OTP_SEND_FAILED",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ProofOfLifeOTPVerifyView(APIView):
    """
    Verify OTP to complete proof of life verification (Step 2B).

    This endpoint verifies the OTP and completes the proof of life verification
    process, creating the final verification record.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Verify OTP and complete (Step 2B)",
        operation_description="Verify OTP to complete proof of life verification",
        tags=["Proof of Life"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "session_token": openapi.Schema(type=openapi.TYPE_STRING),
                "otp_code": openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=["session_token", "otp_code"],
        ),
        responses={
            200: ProofOfLifeVerificationResponseSerializer,
            400: ProofOfLifeErrorResponseSerializer,
            401: ProofOfLifeErrorResponseSerializer,
            404: ProofOfLifeErrorResponseSerializer,
        },
    )
    def post(self, request):
        """Verify OTP and complete proof of life verification."""
        session_token = request.data.get("session_token")
        otp_code = request.data.get("otp_code")

        if not session_token or not otp_code:
            return Response(
                {
                    "success": False,
                    "message": "Session token and OTP code are required",
                    "error_code": "MISSING_PARAMETERS",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            pending_verification = ProofOfLifePendingVerification.objects.get(
                session_token=session_token
            )
        except ProofOfLifePendingVerification.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "message": "Invalid or expired session token",
                    "error_code": "INVALID_SESSION_TOKEN",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Check if session has expired
        if pending_verification.is_expired:
            pending_verification.delete()
            return Response(
                {
                    "success": False,
                    "message": "Verification session has expired. Please start over.",
                    "error_code": "SESSION_EXPIRED",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if OTP was sent
        if not pending_verification.is_otp_sent:
            return Response(
                {
                    "success": False,
                    "message": "OTP has not been sent for this session",
                    "error_code": "OTP_NOT_SENT",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify OTP using existing service
        from apps.users.utils import OTPService

        try:
            success, user_instance, message = OTPService.verify_otp(
                user_id=str(pending_verification.user.id), otp_code=otp_code
            )

            if not success:
                return Response(
                    {
                        "success": False,
                        "message": message,
                        "error_code": "OTP_VERIFICATION_FAILED",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # OTP verification successful - convert pending verification to full verification
            verification = pending_verification.convert_to_full_verification()

            # Log successful verification
            ip_address = self._get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")

            ProofOfLifeAuditLog.log_verification_success(
                user=verification.user,
                verification=verification,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            return Response(
                {
                    "success": True,
                    "message": "Proof of life verification completed successfully - account secured until next month",
                    "verification_id": verification.verification_id,
                    "next_due_date": verification.next_due_date,
                    "verification_accepted": True,
                    "minimum_confidence_met": True,
                    "minimum_liveness_met": True,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": f"Verification completion failed: {str(e)}",
                    "error_code": "VERIFICATION_COMPLETION_FAILED",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class ProofOfLifeHistoryView(APIView):
    """
    Get proof of life verification history for a user.

    Returns paginated list of past verification records
    for display in the user's verification history.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get verification history",
        operation_description="Get proof of life verification history",
        tags=["Proof of Life"],
        responses={
            200: ProofOfLifeHistoryResponseSerializer,
            404: ProofOfLifeErrorResponseSerializer,
        },
        manual_parameters=[
            openapi.Parameter(
                "limit",
                openapi.IN_QUERY,
                description="Number of records to return (default: 10, max: 100)",
                type=openapi.TYPE_INTEGER,
                default=10,
            ),
            openapi.Parameter(
                "offset",
                openapi.IN_QUERY,
                description="Number of records to skip (default: 0)",
                type=openapi.TYPE_INTEGER,
                default=0,
            ),
        ],
    )
    def get(self, request):
        """Get verification history for authenticated user."""
        user = request.user

        # Get pagination parameters
        limit = min(int(request.query_params.get("limit", 10)), 100)
        offset = max(int(request.query_params.get("offset", 0)), 0)

        # Get verification records
        queryset = ProofOfLifeVerification.objects.filter(user=user).order_by(
            "-verification_date"
        )

        total = queryset.count()
        records = queryset[offset : offset + limit]
        has_more = (offset + limit) < total

        # Serialize records
        from .serializers import ProofOfLifeRecordSerializer

        serialized_records = ProofOfLifeRecordSerializer(records, many=True).data

        response_data = {
            "success": True,
            "message": "History retrieved successfully",
            "records": serialized_records,
            "total": total,
            "has_more": has_more,
        }

        return Response(response_data, status=status.HTTP_200_OK)


class ProofOfLifeAdminView(APIView):
    """
    Admin-only endpoints for managing proof of life system.

    Provides endpoints for viewing all verifications, updating settings,
    and performing administrative actions.
    """

    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """Ensure only staff users can access admin endpoints."""
        permissions = super().get_permissions()
        # Add staff permission check
        if not (self.request.user.is_authenticated and self.request.user.is_staff):
            self.permission_denied(self.request, message="Staff access required")
        return permissions

    @swagger_auto_schema(
        operation_summary="List all verifications (Admin)",
        operation_description="Get all proof of life verifications (admin only)",
        tags=["Proof of Life Admin"],
        responses={
            200: ProofOfLifeVerificationModelSerializer(many=True),
            403: ProofOfLifeErrorResponseSerializer,
        },
        manual_parameters=[
            openapi.Parameter(
                "status",
                openapi.IN_QUERY,
                description="Filter by status",
                type=openapi.TYPE_STRING,
                enum=["current", "due_soon", "overdue", "blocked"],
            ),
            openapi.Parameter(
                "limit",
                openapi.IN_QUERY,
                description="Number of records to return",
                type=openapi.TYPE_INTEGER,
                default=50,
            ),
            openapi.Parameter(
                "offset",
                openapi.IN_QUERY,
                description="Number of records to skip",
                type=openapi.TYPE_INTEGER,
                default=0,
            ),
        ],
    )
    def get(self, request):
        """Get all verification records (admin only)."""
        # Get query parameters
        status_filter = request.query_params.get("status")
        limit = min(int(request.query_params.get("limit", 50)), 200)
        offset = max(int(request.query_params.get("offset", 0)), 0)

        # Build queryset
        queryset = ProofOfLifeVerification.objects.select_related("user").order_by(
            "-verification_date"
        )

        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Apply pagination
        total = queryset.count()
        verifications = queryset[offset : offset + limit]

        # Serialize data
        serializer = ProofOfLifeVerificationModelSerializer(verifications, many=True)

        return Response(
            {
                "success": True,
                "message": "Verifications retrieved successfully",
                "data": serializer.data,
                "total": total,
                "limit": limit,
                "offset": offset,
            },
            status=status.HTTP_200_OK,
        )
