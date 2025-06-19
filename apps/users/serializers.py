from datetime import date
from typing import Any

from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing users (admin view).
    Shows essential information without sensitive data.
    """

    full_name = serializers.CharField(source="get_full_name", read_only=True)
    face_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "full_name",
            "phone_number",
            "unique_pin_identifier",
            "face_status",
            "is_active",
            "is_verified",
            "date_joined",
        ]
        read_only_fields = ["id", "unique_pin_identifier", "date_joined"]

    def get_face_status(self, obj: Any) -> str:
        """Return face registration status."""
        if obj.is_face_registered:
            return "registered"
        elif obj.face_added:
            return "pending"
        return "not_registered"


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for single user view (admin).
    Includes all fields except sensitive external_data.
    """

    full_name = serializers.CharField(source="get_full_name", read_only=True)
    short_name = serializers.CharField(source="get_short_name", read_only=True)
    face_status = serializers.SerializerMethodField()
    can_authenticate = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "full_name",
            "short_name",
            "phone_number",
            "date_of_birth",
            "nationality",
            "gender",
            "unique_pin_identifier",
            "person_id",
            "face_added",
            "face_status",
            "is_active",
            "is_verified",
            "can_authenticate",
            "date_joined",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "unique_pin_identifier",
            "person_id",
            "face_added",
            "date_joined",
            "updated_at",
        ]

    def get_face_status(self, obj: Any) -> dict[str, Any]:
        """Return detailed face registration status."""
        return {
            "registered": obj.is_face_registered,
            "face_added": obj.face_added,
            "has_person_id": bool(obj.person_id),
            "can_authenticate": obj.can_authenticate,
        }


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new users (admin only).
    Validates all required fields and formats data properly.
    """

    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "phone_number",
            "date_of_birth",
            "nationality",
            "gender",
        ]

    def validate_email(self, value: str) -> str:
        """Ensure email is unique and properly formatted."""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()

    def validate_phone_number(self, value: str) -> str:
        """Ensure phone number is unique."""
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError(
                "A user with this phone number already exists."
            )
        return value

    def validate_date_of_birth(self, value: date) -> date:
        """Ensure user is at least 18 years old."""
        today = date.today()
        age = (
            today.year
            - value.year
            - ((today.month, today.day) < (value.month, value.day))
        )

        if age < 18:
            raise serializers.ValidationError("User must be at least 18 years old.")
        if age > 120:
            raise serializers.ValidationError("Please enter a valid date of birth.")

        return value

    def validate_first_name(self, value: str) -> str:
        """Clean and validate first name."""
        cleaned = value.strip().title()
        if len(cleaned) < 2:
            raise serializers.ValidationError(
                "First name must be at least 2 characters long."
            )
        return cleaned

    def validate_last_name(self, value: str) -> str:
        """Clean and validate last name."""
        cleaned = value.strip().title()
        if len(cleaned) < 2:
            raise serializers.ValidationError(
                "Last name must be at least 2 characters long."
            )
        return cleaned

    def validate_middle_name(self, value: str | None) -> str | None:
        """Clean middle name if provided."""
        if value:
            return value.strip().title()
        return value


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user information (admin only).
    Allows updating most fields except authentication-related ones.
    """

    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "phone_number",
            "date_of_birth",
            "nationality",
            "gender",
            "is_active",
            "is_verified",
        ]

    def validate_email(self, value: str) -> str:
        """Ensure email is unique (excluding current user)."""
        # Type guard to ensure instance exists and has pk
        if self.instance is None:
            raise serializers.ValidationError("No instance available for validation.")

        if not hasattr(self.instance, "pk"):
            raise serializers.ValidationError("Invalid instance type.")

        user = self.instance
        if hasattr(user, "pk"):
            if User.objects.filter(email__iexact=value).exclude(pk=user.pk).exists():
                raise serializers.ValidationError(
                    "A user with this email already exists."
                )
        return value.lower()

    def validate_phone_number(self, value: str) -> str:
        """Ensure phone number is unique (excluding current user)."""
        # Type guard to ensure instance exists and has pk
        if self.instance is None:
            raise serializers.ValidationError("No instance available for validation.")

        if not hasattr(self.instance, "pk"):
            raise serializers.ValidationError("Invalid instance type.")
        user = self.instance
        if hasattr(user, "pk"):
            if User.objects.filter(phone_number=value).exclude(pk=user.pk).exists():
                raise serializers.ValidationError(
                    "A user with this phone number already exists."
                )
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user's own profile (read-only).
    Limited fields for security - users can't modify their own data.
    """

    full_name = serializers.CharField(source="get_full_name", read_only=True)
    face_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "full_name",
            "phone_number",
            "unique_pin_identifier",
            "face_status",
            "is_verified",
            "date_joined",
        ]
        read_only_fields = [
            "id",
            "email",
            "full_name",
            "phone_number",
            "unique_pin_identifier",
            "face_status",
            "is_verified",
            "date_joined",
        ]

    def get_face_status(self, obj: Any) -> dict[str, Any]:
        """Return face registration status for user."""
        return {
            "registered": obj.is_face_registered,
            "can_authenticate": obj.can_authenticate,
        }
