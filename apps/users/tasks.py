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
