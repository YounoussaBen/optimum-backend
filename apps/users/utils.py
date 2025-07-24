"""
OTP utilities for generating, validating, and managing One-Time Passwords.
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import OTP, User


class OTPService:
    """Service class for OTP operations."""

    @staticmethod
    def generate_otp(
        user_id: str, delivery_method: str
    ) -> tuple[bool, OTP | None, str]:
        """
        Generate a new OTP for a user.

        Args:
            user_id (str): User ID (UUID as string)
            delivery_method (str): 'sms' or 'email'

        Returns:
            Tuple[bool, Optional[OTP], str]: (success, otp_instance, message)
        """
        try:
            # Validate delivery method
            if delivery_method not in ["sms", "email"]:
                return False, None, "Invalid delivery method. Must be 'sms' or 'email'"

            # Get user
            try:
                user = User.objects.get(id=user_id, is_active=True)
            except User.DoesNotExist:
                return False, None, "User not found or inactive"

            # Validate user has required contact info
            if delivery_method == "email" and not user.email:
                return False, None, "User has no email address"
            elif delivery_method == "sms" and not user.phone_number:
                return False, None, "User has no phone number"

            with transaction.atomic():
                # Invalidate any existing valid OTPs for this user
                OTP.objects.filter(
                    user=user,
                    is_used=False,
                    is_expired=False,
                    expires_at__gt=timezone.now(),
                ).update(is_expired=True)

                # Create new OTP
                otp = OTP.objects.create(user=user, delivery_method=delivery_method)

                return True, otp, "OTP generated successfully"

        except Exception as e:
            return False, None, f"Error generating OTP: {str(e)}"

    @staticmethod
    def verify_otp(user_id: str, otp_code: str) -> tuple[bool, User | None, str]:
        """
        Verify an OTP code for a user.

        Args:
            user_id (str): User ID (UUID as string)
            otp_code (str): 6-digit OTP code

        Returns:
            Tuple[bool, Optional[User], str]: (success, user_instance, message)
        """
        try:
            # Get user
            try:
                user = User.objects.get(id=user_id, is_active=True)
            except User.DoesNotExist:
                return False, None, "User not found or inactive"

            # Find valid OTP
            try:
                otp = OTP.objects.get(
                    user=user,
                    code=otp_code,
                    is_used=False,
                    is_expired=False,
                    expires_at__gt=timezone.now(),
                )
            except OTP.DoesNotExist:
                return False, None, "Invalid OTP code"

            # Double-check OTP validity (in case of race conditions)
            if not otp.is_valid:
                return False, None, "OTP has expired"

            with transaction.atomic():
                # Mark OTP as used
                otp.mark_as_used()

                # Invalidate any other OTPs for this user
                OTP.objects.filter(user=user, is_used=False, is_expired=False).exclude(
                    id=otp.id
                ).update(is_expired=True)

                return True, user, "OTP verified successfully"

        except Exception as e:
            return False, None, f"Error verifying OTP: {str(e)}"

    @staticmethod
    def cleanup_expired_otps():
        """
        Clean up expired OTPs from the database.
        This should be run periodically as a background task.
        """
        try:
            # Mark expired OTPs
            expired_count = OTP.objects.filter(
                expires_at__lt=timezone.now(), is_expired=False
            ).update(is_expired=True)

            # Optionally delete very old OTPs (older than 24 hours)
            deleted_count, _ = OTP.objects.filter(
                created_at__lt=timezone.now() - timedelta(hours=24)
            ).delete()

            return f"Marked {expired_count} OTPs as expired, deleted {deleted_count} old OTPs"

        except Exception as e:
            return f"Error cleaning up OTPs: {str(e)}"


def mask_contact_info(contact: str, contact_type: str) -> str:
    """
    Mask contact information for display purposes.

    Args:
        contact (str): The contact information (email or phone)
        contact_type (str): 'email' or 'sms'

    Returns:
        str: Masked contact information
    """
    if contact_type == "email":
        if "@" not in contact:
            return "***@***.***"

        local, domain = contact.split("@")
        if len(local) <= 3:
            masked_local = local[0] + "*" * (len(local) - 1)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"

    elif contact_type == "sms":
        # Remove any non-digit characters for processing
        digits_only = "".join(filter(str.isdigit, contact))

        if len(digits_only) >= 7:
            # Show first 3 and last 2 digits, mask the middle
            visible_start = digits_only[:3]
            visible_end = digits_only[-2:]
            masked_middle = "*" * (len(digits_only) - 5)
            masked_digits = visible_start + masked_middle + visible_end

            # Preserve the original format structure
            if contact.startswith("+"):
                return f"+{masked_digits[:3]} {masked_digits[3:5]} {masked_digits[5:7]} **{masked_digits[-2:]}"
            else:
                return masked_digits
        else:
            # For shorter numbers, just mask most digits
            return contact[:-2] + "**"

    return "***"
