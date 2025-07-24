import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_id, email):
    """
    Send welcome email to new user
    """
    try:
        subject = "Welcome to OptimumIT!"
        message = (
            "Welcome to OptimumIT platform! Your account has been created successfully."
        )

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        logger.info(f"Welcome email sent successfully to user {user_id}")
        return {"status": "success", "user_id": user_id, "email": email}

    except Exception as exc:
        logger.error(f"Failed to send welcome email to user {user_id}: {exc}")
        self.retry(countdown=60, exc=exc)


@shared_task
def cleanup_expired_sessions():
    """
    Clean up expired user sessions
    """
    try:
        from django.contrib.sessions.models import Session
        from django.utils import timezone

        expired_sessions = Session.objects.filter(expire_date__lt=timezone.now())
        count = expired_sessions.count()
        expired_sessions.delete()

        logger.info(f"Cleaned up {count} expired sessions")
        return {"status": "success", "cleaned_sessions": count}

    except Exception as exc:
        logger.error(f"Failed to cleanup expired sessions: {exc}")
        raise


@shared_task
def process_face_verification_cleanup():
    """
    Clean up expired face verification records
    """
    try:
        from django.utils import timezone

        from apps.users.models import User

        # Find users whose verification has expired
        expired_users = User.objects.filter(
            is_verified=True, verification_expires_at__lt=timezone.now()
        )

        count = expired_users.update(is_verified=False, verification_expires_at=None)

        logger.info(f"Reset face verification for {count} expired users")
        return {"status": "success", "reset_count": count}

    except Exception as exc:
        logger.error(f"Failed to cleanup face verifications: {exc}")
        raise


@shared_task(bind=True, max_retries=3)
def send_otp_email(self, user_id, email, otp_code):
    """
    Send OTP code via email
    """
    try:
        subject = "Your OptimumIT OTP Code"
        message = f"""
        Your OTP code is: {otp_code}

        This code will expire in 60 seconds.
        Please do not share this code with anyone.

        If you did not request this code, please ignore this email.
        """

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        logger.info(f"OTP email sent successfully to user {user_id}")
        return {"status": "success", "user_id": user_id, "email": email}

    except Exception as exc:
        logger.error(f"Failed to send OTP email to user {user_id}: {exc}")
        self.retry(countdown=10, exc=exc)


@shared_task(bind=True, max_retries=3)
def send_otp_sms(self, user_id, phone_number, otp_code):
    """
    Send OTP code via SMS

    Note: This is a placeholder for SMS integration with Azure Communication Services
    or other SMS providers. Implementation depends on the chosen SMS service.
    """
    try:
        # TODO: Implement SMS sending using Azure Communication Services or another provider
        # For now, we'll log the SMS that would be sent

        sms_message = f"Your OptimumIT OTP code is: {otp_code}. Expires in 60 seconds."

        # Placeholder for actual SMS sending
        # Example with Azure Communication Services:
        # from azure.communication.sms import SmsClient
        # sms_client = SmsClient.from_connection_string(settings.AZURE_COMMUNICATION_CONNECTION_STRING)
        # sms_responses = sms_client.send(
        #     from_=settings.SMS_FROM_NUMBER,
        #     to=[phone_number],
        #     message=sms_message
        # )

        # For development/testing - log the SMS
        logger.info(f"SMS would be sent to {phone_number}: {sms_message}")

        # Simulate successful SMS sending
        logger.info(f"OTP SMS sent successfully to user {user_id}")
        return {"status": "success", "user_id": user_id, "phone": phone_number}

    except Exception as exc:
        logger.error(f"Failed to send OTP SMS to user {user_id}: {exc}")
        self.retry(countdown=10, exc=exc)


@shared_task
def cleanup_expired_otps():
    """
    Clean up expired OTP records
    """
    try:
        from apps.users.utils import OTPService

        result = OTPService.cleanup_expired_otps()
        logger.info(f"OTP cleanup completed: {result}")

        return {"status": "success", "message": result}

    except Exception as exc:
        logger.error(f"Failed to cleanup expired OTPs: {exc}")
        raise
