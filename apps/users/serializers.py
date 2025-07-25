import csv
import io
from datetime import date
from typing import Any

from django.contrib.auth import authenticate, get_user_model
from django.db import models
from rest_framework import serializers

from core.services.storage import (
    delete_profile_picture,
    update_profile_picture,
    upload_profile_picture,
)

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
            "person_id",
            "face_status",
            "profile_picture",
            "address",
            "city",
            "postal_code",
            "country",
            "is_active",
            "is_verified",
            "date_joined",
        ]
        read_only_fields = ["id", "unique_pin_identifier", "date_joined", "person_id"]

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
            "profile_picture",
            "address",
            "city",
            "postal_code",
            "country",
            "unique_pin_identifier",
            "person_id",
            "face_added",
            "face_status",
            "is_active",
            "is_verified",
            "verification_expires_at",
            "can_authenticate",
            "date_joined",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "unique_pin_identifier",
            "person_id",
            "face_added",
            "verification_expires_at",
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
    Supports base64 profile picture upload.
    """

    profile_picture_base64 = serializers.CharField(
        write_only=True,
        required=False,
        help_text="Base64 encoded profile picture image",
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "phone_number",
            "date_of_birth",
            "nationality",
            "gender",
            "profile_picture",
            "profile_picture_base64",
            "address",
            "city",
            "postal_code",
            "country",
        ]
        read_only_fields = ["id", "profile_picture"]

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

    def create(self, validated_data):
        """Create user with optional profile picture upload."""
        profile_picture_base64 = validated_data.pop("profile_picture_base64", None)

        user = super().create(validated_data)

        # Upload profile picture if provided
        if profile_picture_base64:
            try:
                profile_picture_url = upload_profile_picture(
                    str(user.id), profile_picture_base64
                )
                user.profile_picture = profile_picture_url
                user.save(update_fields=["profile_picture"])
            except Exception as e:
                # Log error but don't fail user creation
                import logging

                logger = logging.getLogger(__name__)
                logger.error(
                    f"Failed to upload profile picture for user {user.id}: {str(e)}"
                )

        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user information (admin only).
    Allows updating most fields except authentication-related ones.
    Supports base64 profile picture upload and removal.
    """

    profile_picture_base64 = serializers.CharField(
        write_only=True,
        required=False,
        help_text="Base64 encoded profile picture image. Pass empty string to remove profile picture.",
    )

    remove_profile_picture = serializers.BooleanField(
        write_only=True,
        required=False,
        default=False,
        help_text="Set to true to remove the current profile picture",
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "middle_name",
            "last_name",
            "phone_number",
            "date_of_birth",
            "nationality",
            "gender",
            "profile_picture",
            "profile_picture_base64",
            "remove_profile_picture",
            "address",
            "city",
            "postal_code",
            "country",
            "is_active",
            "is_verified",
            "verification_expires_at",
        ]
        read_only_fields = ["id", "profile_picture"]

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

    def update(self, instance, validated_data):
        """Update user with optional profile picture upload or removal."""
        profile_picture_base64 = validated_data.pop("profile_picture_base64", None)
        remove_profile_picture = validated_data.pop("remove_profile_picture", False)

        # Handle profile picture removal
        if remove_profile_picture:
            try:
                if instance.profile_picture:
                    delete_profile_picture(instance.profile_picture)
                    validated_data["profile_picture"] = None
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.info(f"Removed profile picture for user {instance.id}")
            except Exception as e:
                # Log error but don't fail user update
                import logging

                logger = logging.getLogger(__name__)
                logger.error(
                    f"Failed to remove profile picture for user {instance.id}: {str(e)}"
                )

        # Handle profile picture update (only if not removing)
        elif profile_picture_base64:
            # Support empty string as removal signal
            if profile_picture_base64.strip() == "":
                try:
                    if instance.profile_picture:
                        delete_profile_picture(instance.profile_picture)
                        validated_data["profile_picture"] = None
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.info(
                            f"Removed profile picture for user {instance.id} (empty string)"
                        )
                except Exception as e:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.error(
                        f"Failed to remove profile picture for user {instance.id}: {str(e)}"
                    )
            else:
                # Upload new profile picture
                try:
                    profile_picture_url = update_profile_picture(
                        str(instance.id),
                        instance.profile_picture,
                        profile_picture_base64,
                    )
                    validated_data["profile_picture"] = profile_picture_url
                except Exception as e:
                    # Log error but don't fail user update
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.error(
                        f"Failed to update profile picture for user {instance.id}: {str(e)}"
                    )

        return super().update(instance, validated_data)


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
            "profile_picture",
            "address",
            "city",
            "postal_code",
            "country",
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


class AdminLoginSerializer(serializers.Serializer):
    """
    Serializer for admin email/password authentication.
    Only allows staff/superuser accounts to login.
    """

    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            # Authenticate user
            user = authenticate(
                request=self.context.get("request"),
                username=email,  # User model uses email as USERNAME_FIELD
                password=password,
            )

            if not user:
                raise serializers.ValidationError(
                    "Invalid email or password.", code="authorization"
                )

            if not user.is_active:
                raise serializers.ValidationError(
                    "User account is disabled.", code="authorization"
                )

            # Check if user is staff or superuser
            if not (user.is_staff or user.is_superuser):
                raise serializers.ValidationError(
                    "Access denied. Admin privileges required.", code="authorization"
                )

            attrs["user"] = user
            return attrs
        else:
            raise serializers.ValidationError(
                "Must include email and password.", code="authorization"
            )


class AdminLoginResponseSerializer(serializers.Serializer):
    """
    Serializer for admin login response.
    """

    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        user = obj["user"]
        return {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.get_full_name(),
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
        }


class TokenRefreshResponseSerializer(serializers.Serializer):
    """
    Serializer for token refresh response.
    """

    access_token = serializers.CharField()


class DashboardStatsSerializer(serializers.Serializer):
    """
    Serializer for dashboard statistics response.
    """

    total_users = serializers.IntegerField()
    verified_users = serializers.IntegerField()
    failed_verifications = serializers.IntegerField()
    active_faces = serializers.IntegerField()
    total_users_change = serializers.FloatField(required=False, allow_null=True)
    verified_users_change = serializers.FloatField(required=False, allow_null=True)
    failed_verifications_change = serializers.FloatField(
        required=False, allow_null=True
    )
    active_faces_change = serializers.FloatField(required=False, allow_null=True)


class VerificationDataPointSerializer(serializers.Serializer):
    """
    Serializer for verification chart data points.
    """

    date = serializers.DateField()
    verifications = serializers.IntegerField()
    failures = serializers.IntegerField()


class RecentActivitySerializer(serializers.Serializer):
    """
    Serializer for recent activity items.
    """

    id = serializers.CharField()
    type = serializers.ChoiceField(
        choices=[
            ("user_created", "User Created"),
            ("user_verified", "User Verified"),
            ("face_added", "Face Added"),
            ("training_completed", "Training Completed"),
            ("verification_failed", "Verification Failed"),
        ]
    )
    message = serializers.CharField()
    timestamp = serializers.DateTimeField()
    user_id = serializers.CharField(required=False, allow_null=True)
    admin_id = serializers.CharField(required=False, allow_null=True)


class DashboardDataSerializer(serializers.Serializer):
    """
    Serializer for complete dashboard response.
    """

    stats = DashboardStatsSerializer()
    verification_chart = VerificationDataPointSerializer(many=True)
    recent_activities = RecentActivitySerializer(many=True)


class DynamicUserCreationSerializer(serializers.ModelSerializer):
    """
    Dynamic serializer for bulk user creation.
    Automatically includes all user-editable fields from the User model,
    respecting required/optional field definitions.
    """

    class Meta:
        model = User
        fields: list[str] = []  # Will be set dynamically
        extra_kwargs: dict[str, dict[str, bool]] = {}  # Will be set dynamically

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_dynamic_fields()

    def _setup_dynamic_fields(self):
        """Dynamically configure fields based on User model introspection."""
        # Get all model fields
        model_fields = self.Meta.model._meta.get_fields()

        # Fields to exclude (auto-generated, non-editable, or relations)
        excluded_fields = {
            "id",
            "password",
            "last_login",
            "date_joined",
            "updated_at",
            "unique_pin_identifier",
            "groups",
            "user_permissions",
            "logentry",
        }

        # Build field list and extra_kwargs
        fields: list[str] = []
        extra_kwargs: dict[str, dict[str, bool]] = {}

        for field in model_fields:
            # Skip excluded fields and reverse relations
            if (
                field.name in excluded_fields
                or hasattr(field, "related_model")
                and field.many_to_one is False
            ):
                continue

            fields.append(field.name)

            # Determine if field is required
            field_kwargs = {}

            # Check if field allows blank/null or has default
            if hasattr(field, "blank") and field.blank:
                field_kwargs["required"] = False
            elif hasattr(field, "null") and field.null:
                field_kwargs["required"] = False
            elif hasattr(field, "default") and field.default != models.NOT_PROVIDED:
                field_kwargs["required"] = False

            if field_kwargs:
                extra_kwargs[field.name] = field_kwargs

        # Update Meta class
        self.Meta.fields = fields
        self.Meta.extra_kwargs = extra_kwargs

        # Regenerate fields
        self._declared_fields = {}
        self.fields.clear()
        self.fields.update(self.get_fields())


class BulkUserImportSerializer(serializers.Serializer):
    """
    Serializer for bulk user import endpoint.
    Accepts either JSON data or CSV file.
    """

    # For JSON input
    users_data = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="List of user objects to create (JSON format)",
    )

    # For CSV input
    csv_file = serializers.FileField(
        required=False, help_text="CSV file containing user data"
    )

    def validate(self, attrs):
        """Ensure either JSON data or CSV file is provided, but not both."""
        users_data = attrs.get("users_data")
        csv_file = attrs.get("csv_file")

        if not users_data and not csv_file:
            raise serializers.ValidationError(
                "Either 'users_data' (JSON) or 'csv_file' must be provided."
            )

        if users_data and csv_file:
            raise serializers.ValidationError(
                "Provide either 'users_data' (JSON) or 'csv_file', not both."
            )

        return attrs

    def parse_csv_data(self, csv_file):
        """Parse CSV file and return list of user data dictionaries."""
        try:
            # Read CSV content
            csv_content = csv_file.read().decode("utf-8")
            csv_file.seek(0)  # Reset file pointer

            # Parse CSV
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            users_data = []

            for row in csv_reader:
                # Remove empty values and strip whitespace
                user_data = {k.strip(): v.strip() for k, v in row.items() if v.strip()}

                if user_data:  # Skip completely empty rows
                    users_data.append(user_data)

            return users_data

        except UnicodeDecodeError as e:
            raise serializers.ValidationError("CSV file must be UTF-8 encoded.") from e
        except Exception as e:
            raise serializers.ValidationError(
                f"Error parsing CSV file: {str(e)}"
            ) from e


class BulkUserImportResponseSerializer(serializers.Serializer):
    """Response serializer for bulk user import."""

    success_count = serializers.IntegerField()
    error_count = serializers.IntegerField()
    total_processed = serializers.IntegerField()
    created_users = UserListSerializer(many=True)
    errors = serializers.ListField(
        child=serializers.DictField(),
        help_text="List of errors with row numbers and details",
    )  # type: ignore[assignment]


class GenerateOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP generation request.
    """

    user_id = serializers.UUIDField(help_text="User ID (UUID)")
    method = serializers.ChoiceField(
        choices=[("sms", "SMS"), ("email", "Email")],
        help_text="Delivery method for OTP (sms or email)",
    )

    def validate_user_id(self, value):
        """Validate that user exists and is active."""
        try:
            User.objects.get(id=value, is_active=True)
            return str(value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found or inactive") from None


class GenerateOTPResponseSerializer(serializers.Serializer):
    """
    Serializer for OTP generation response.
    """

    success = serializers.BooleanField()
    message = serializers.CharField()
    contact = serializers.CharField(required=False)
    expires_in = serializers.IntegerField(required=False)


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP verification request.
    """

    user_id = serializers.UUIDField(help_text="User ID (UUID)")
    otp_code = serializers.CharField(
        max_length=6, min_length=6, help_text="6-digit OTP code"
    )

    def validate_user_id(self, value):
        """Validate that user exists and is active."""
        try:
            User.objects.get(id=value, is_active=True)
            return str(value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found or inactive") from None

    def validate_otp_code(self, value):
        """Validate OTP code format."""
        if not value.isdigit():
            raise serializers.ValidationError("OTP code must contain only digits")
        return value


class VerifyOTPResponseSerializer(serializers.Serializer):
    """
    Serializer for OTP verification response.
    """

    success = serializers.BooleanField()
    message = serializers.CharField()
    access_token = serializers.CharField(required=False)
    refresh_token = serializers.CharField(required=False)
    user = serializers.SerializerMethodField(required=False)

    def get_user(self, obj):
        """Return user information on successful verification."""
        if obj.get("success") and obj.get("user"):
            user = obj["user"]
            return {
                "id": str(user.id),
                "name": user.get_full_name(),
                "email": user.email,
                "phone": user.phone_number,
            }
        return None


class OTPErrorResponseSerializer(serializers.Serializer):
    """
    Serializer for OTP error responses.
    """

    success = serializers.BooleanField(default=False)
    message = serializers.CharField()
