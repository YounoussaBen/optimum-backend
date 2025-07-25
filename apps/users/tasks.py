import logging

from azure.communication.email import EmailClient
from azure.communication.sms import SmsClient
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
    Send OTP code via email using Azure Communication Services
    """
    try:
        # For development, use Django's console backend if configured
        if hasattr(settings, "EMAIL_BACKEND") and "console" in settings.EMAIL_BACKEND:
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
            logger.info(f"OTP email sent to console for user {user_id}")
            return {"status": "success", "user_id": user_id, "email": email}

        # Use Azure Communication Services for production
        email_client = EmailClient.from_connection_string(
            settings.AZURE_COMMUNICATION_CONNECTION_STRING
        )

        email_message = {
            "senderAddress": settings.AZURE_EMAIL_FROM_ADDRESS,
            "recipients": {"to": [{"address": email}]},
            "content": {
                "subject": "Your OptimumIT OTP Code",
                "plainText": f"""
                Your OTP code is: {otp_code}

                This code will expire in 60 seconds.
                Please do not share this code with anyone.

                If you did not request this code, please ignore this email.
                """,
                "html": f"""
                <html>
                <body>
                    <h2>Your OptimumIT OTP Code</h2>
                    <p><strong>Your OTP code is: {otp_code}</strong></p>
                    <p>This code will expire in 60 seconds.</p>
                    <p>Please do not share this code with anyone.</p>
                    <p><em>If you did not request this code, please ignore this email.</em></p>
                </body>
                </html>
                """,
            },
        }

        poller = email_client.begin_send(message=email_message)
        result = poller.result()

        # Handle result which is a dict from Azure Communication Services
        message_id = result.get("id", "") if isinstance(result, dict) else ""

        logger.info(
            f"OTP email sent successfully to user {user_id} at {email} - Message ID: {message_id}"
        )
        return {
            "status": "success",
            "user_id": user_id,
            "email": email,
            "message_id": message_id,
        }

    except Exception as exc:
        logger.error(f"Failed to send OTP email to user {user_id}: {exc}")
        self.retry(countdown=10, exc=exc)


@shared_task(bind=True, max_retries=3)
def send_otp_sms(self, user_id, phone_number, otp_code):
    """
    Send OTP code via SMS using Azure Communication Services
    """
    try:
        # Check if SMS phone number is configured
        if not settings.AZURE_SMS_FROM_NUMBER:
            logger.warning(
                f"SMS phone number not configured. Cannot send SMS to user {user_id}"
            )
            # Log the SMS that would be sent for development
            sms_message = (
                f"Your OptimumIT OTP code is: {otp_code}. Expires in 60 seconds."
            )
            logger.info(f"SMS would be sent to {phone_number}: {sms_message}")
            return {
                "status": "success",
                "user_id": user_id,
                "phone": phone_number,
                "note": "SMS phone number not configured",
            }

        sms_message = f"Your OptimumIT OTP code is: {otp_code}. Expires in 60 seconds."

        # Initialize Azure SMS client
        sms_client = SmsClient.from_connection_string(
            settings.AZURE_COMMUNICATION_CONNECTION_STRING
        )

        # Send SMS
        sms_responses = sms_client.send(
            from_=settings.AZURE_SMS_FROM_NUMBER,
            to=[phone_number],
            message=sms_message,
            enable_delivery_report=True,
            tag=f"otp-{user_id}",
        )

        # Check if SMS was sent successfully
        for sms_response in sms_responses:
            if sms_response.successful:
                logger.info(
                    f"OTP SMS sent successfully to user {user_id} at {phone_number}"
                )
                return {
                    "status": "success",
                    "user_id": user_id,
                    "phone": phone_number,
                    "message_id": sms_response.message_id,
                }
            else:
                logger.error(
                    f"Failed to send SMS to {phone_number}: {sms_response.error_message}"
                )
                raise Exception(f"SMS sending failed: {sms_response.error_message}")

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
