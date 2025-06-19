# apps/users/middleware.py

import logging

from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)


class FaceVerificationExpirationMiddleware:
    """
    Middleware to check and expire face verification on each request.
    Only checks authenticated users with face verification enabled.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check verification expiration for authenticated users
        if hasattr(request, "user") and request.user.is_authenticated:
            user = request.user

            # Only check for non-staff users (normal users)
            if not user.is_staff and hasattr(user, "verification_expires_at"):
                # Check if verification has expired
                if user.is_verified and user.is_verification_expired:
                    logger.info(f"Face verification expired for user {user.id}")
                    user.expire_verification()

        response = self.get_response(request)
        return response
