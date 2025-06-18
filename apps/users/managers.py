from typing import TypeVar

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager

_T = TypeVar("_T", bound=AbstractBaseUser)


class UserManager(BaseUserManager[_T]):
    """
    Custom manager for User model that handles creation without passwords.
    """

    def _create_user(self, email, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        password = extra_fields.pop("password", None)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_user(self, email, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", False)
        return self._create_user(email, **extra_fields)

    def create_superuser(self, email, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", True)

        if not extra_fields["is_staff"]:
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields["is_superuser"]:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, **extra_fields)

    def get_by_pin(self, pin):
        try:
            return self.get(unique_pin_identifier=pin)
        except self.model.DoesNotExist:
            return None

    def active_users(self):
        return self.filter(is_active=True)

    def verified_users(self):
        return self.filter(is_verified=True, is_active=True)

    def face_registered_users(self):
        return self.filter(is_active=True, is_verified=True, face_added=True).exclude(
            person_id=""
        )

    def pending_verification(self):
        return self.filter(is_active=True, is_verified=False)
