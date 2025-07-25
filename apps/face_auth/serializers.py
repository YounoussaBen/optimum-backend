"""
Serializers for Face Authentication API endpoints.
Handles validation, serialization, and deserialization of face auth data.
"""

import base64

from django.core.validators import RegexValidator
from rest_framework import serializers


class PersonGroupCreateSerializer(serializers.Serializer):
    """
    Serializer for creating person groups.
    Allows optional person_group_id or uses default from settings.
    """

    person_group_id = serializers.CharField(
        max_length=64,
        required=False,
        allow_blank=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9-_]+$",
                message="Person group ID can only contain lowercase letters, numbers, hyphens, and underscores.",
            )
        ],
        help_text="Optional custom person group ID. If not provided, uses default from settings.",
    )

    name = serializers.CharField(
        max_length=128,
        required=False,
        allow_blank=True,
        help_text="Human-readable name for the person group.",
    )

    def validate_person_group_id(self, value):
        """Validate person group ID format."""
        if value and len(value) < 1:
            raise serializers.ValidationError(
                "Person group ID cannot be empty if provided."
            )
        return value


class PersonGroupResponseSerializer(serializers.Serializer):
    """Serializer for person group creation response."""

    person_group_id = serializers.CharField()
    name = serializers.CharField()
    created = serializers.BooleanField(default=True)


class PersonGroupInfoSerializer(serializers.Serializer):
    """Serializer for person group information response."""

    personGroupId = serializers.CharField()
    name = serializers.CharField()


class PersonGroupListSerializer(serializers.Serializer):
    """Serializer for listing person groups."""

    personGroupId = serializers.CharField()
    name = serializers.CharField()


class TrainingStatusSerializer(serializers.Serializer):
    """Serializer for training status response."""

    status = serializers.ChoiceField(
        choices=["notstarted", "running", "succeeded", "failed"]
    )
    createdDateTime = serializers.DateTimeField(required=False)
    lastActionDateTime = serializers.DateTimeField(required=False)
    message = serializers.CharField(required=False, allow_blank=True)


class AddUserToPersonGroupSerializer(serializers.Serializer):
    """
    Serializer for adding a User to a person group.
    This creates the person in Azure and updates the User's person_id.
    """

    user_id = serializers.UUIDField(help_text="User ID to add to person group")

    person_group_id = serializers.CharField(
        max_length=64,
        required=False,
        allow_blank=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9-_]+$",
                message="Person group ID can only contain lowercase letters, numbers, hyphens, and underscores.",
            )
        ],
        help_text="Optional person group ID. Uses default if not provided.",
    )


class AddUserToPersonGroupResponseSerializer(serializers.Serializer):
    """Serializer for add user to person group response."""

    user_id = serializers.UUIDField()
    person_id = serializers.CharField()
    person_group_id = serializers.CharField()
    message = serializers.CharField()


class FaceAuthenticationSerializer(serializers.Serializer):
    """
    Serializer for face + PIN authentication.
    Used for user login via face verification.
    """

    pin = serializers.CharField(
        max_length=9,
        min_length=8,
        validators=[
            RegexValidator(regex=r"^\d{8,9}$", message="PIN must be 8 or 9 digits.")
        ],
        help_text="8 or 9-digit PIN identifier",
    )
    person_group_id = serializers.CharField(
        max_length=64,
        required=False,
        allow_blank=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9-_]+$",
                message="Person group ID can only contain lowercase letters, numbers, hyphens, and underscores.",
            )
        ],
        help_text="Optional person group ID. Uses default if not provided.",
    )

    image_url = serializers.URLField(
        required=False, allow_blank=True, help_text="URL of the face image"
    )

    image_data = serializers.CharField(
        required=False, allow_blank=True, help_text="Base64 encoded face image"
    )

    image_file = serializers.ImageField(
        required=False, allow_null=True, help_text="Face image file upload"
    )

    confidence_threshold = serializers.FloatField(
        default=0.8,
        min_value=0.0,
        max_value=1.0,
        help_text="Minimum confidence score for successful verification (0.0-1.0)",
    )

    def validate(self, data):
        """Ensure exactly one image source is provided."""
        sources = [
            data.get("image_url"),
            data.get("image_data"),
            data.get("image_file"),
        ]
        provided_sources = [source for source in sources if source]

        if len(provided_sources) != 1:
            raise serializers.ValidationError(
                "Exactly one image source must be provided: image_url, image_data, or image_file."
            )

        return data

    def validate_image_data(self, value):
        """Validate base64 image data."""
        if not value:
            return value

        # Remove data URL prefix if present
        if value.startswith("data:image/"):
            try:
                value = value.split(",", 1)[1]
            except IndexError:
                raise serializers.ValidationError("Invalid data URL format.") from None

        # Validate base64 format
        try:
            base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 image data.") from None

        return value

    def validate_image_file(self, value):
        """Validate uploaded face image file."""
        if not value:
            return value

        # Check file size (max 6MB)
        max_size = 6 * 1024 * 1024  # 6MB
        if value.size > max_size:
            raise serializers.ValidationError(
                "Image file too large. Maximum size is 6MB."
            )

        # Check file type
        allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/bmp"]
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(
                f"Unsupported image format. Allowed: {', '.join(allowed_types)}"
            )

        return value


class FaceAuthenticationResponseSerializer(serializers.Serializer):
    """Serializer for face authentication response with adaptive learning info."""

    success = serializers.BooleanField()
    user_id = serializers.UUIDField(required=False)
    access_token = serializers.CharField(required=False)
    refresh_token = serializers.CharField(required=False)
    confidence_score = serializers.FloatField(required=False)
    message = serializers.CharField()

    adaptive_learning_performed = serializers.BooleanField(
        required=False,
        help_text="Whether adaptive learning was performed (face added for improvement)",
    )
    auth_faces_count = serializers.IntegerField(
        required=False,
        help_text="Current number of faces added during authentication (max 100)",
    )


class FaceVerificationSerializer(serializers.Serializer):
    """
    Serializer for face verification (for sensitive operations).
    Used when user needs to verify their identity for specific actions.
    """

    user_id = serializers.UUIDField(
        required=False,
        help_text="User ID to verify. If not provided, uses current authenticated user.",
    )

    person_group_id = serializers.CharField(
        max_length=64,
        required=False,
        allow_blank=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9-_]+$",
                message="Person group ID can only contain lowercase letters, numbers, hyphens, and underscores.",
            )
        ],
        help_text="Optional person group ID. Uses default if not provided.",
    )

    image_url = serializers.URLField(
        required=False, allow_blank=True, help_text="URL of the face image"
    )

    image_data = serializers.CharField(
        required=False, allow_blank=True, help_text="Base64 encoded face image"
    )

    image_file = serializers.ImageField(
        required=False, allow_null=True, help_text="Face image file upload"
    )

    confidence_threshold = serializers.FloatField(
        default=0.8,
        min_value=0.0,
        max_value=1.0,
        help_text="Minimum confidence score for successful verification (0.0-1.0)",
    )

    def validate(self, data):
        """Ensure exactly one image source is provided."""
        sources = [
            data.get("image_url"),
            data.get("image_data"),
            data.get("image_file"),
        ]
        provided_sources = [source for source in sources if source]

        if len(provided_sources) != 1:
            raise serializers.ValidationError(
                "Exactly one image source must be provided: image_url, image_data, or image_file."
            )

        return data

    def validate_image_data(self, value):
        """Validate base64 image data."""
        if not value:
            return value

        # Remove data URL prefix if present
        if value.startswith("data:image/"):
            try:
                value = value.split(",", 1)[1]
            except IndexError:
                raise serializers.ValidationError("Invalid data URL format.") from None

        # Validate base64 format
        try:
            base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 image data.") from None

        return value

    def validate_image_file(self, value):
        """Validate uploaded face image file."""
        if not value:
            return value

        # Check file size (max 6MB)
        max_size = 6 * 1024 * 1024  # 6MB
        if value.size > max_size:
            raise serializers.ValidationError(
                "Image file too large. Maximum size is 6MB."
            )

        # Check file type
        allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/bmp"]
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(
                f"Unsupported image format. Allowed: {', '.join(allowed_types)}"
            )

        return value


class FaceVerificationResponseSerializer(serializers.Serializer):
    """Serializer for face verification response."""

    verified = serializers.BooleanField()
    confidence_score = serializers.FloatField(required=False)
    message = serializers.CharField()
    user_id = serializers.UUIDField(required=False)
    expires_at = serializers.DateTimeField(required=False)


class AddUserFaceSerializer(serializers.Serializer):
    """
    Serializer for adding a face to a user.
    Used by admin to register user faces.
    """

    user_id = serializers.UUIDField(help_text="User ID to add face to")

    person_group_id = serializers.CharField(
        max_length=64,
        required=False,
        allow_blank=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9-_]+$",
                message="Person group ID can only contain lowercase letters, numbers, hyphens, and underscores.",
            )
        ],
        help_text="Optional person group ID. Uses default if not provided.",
    )

    image_url = serializers.URLField(
        required=False, allow_blank=True, help_text="URL of the face image"
    )

    image_data = serializers.CharField(
        required=False, allow_blank=True, help_text="Base64 encoded face image"
    )

    image_file = serializers.ImageField(
        required=False, allow_null=True, help_text="Face image file upload"
    )

    def validate(self, data):
        """Ensure exactly one image source is provided."""
        sources = [
            data.get("image_url"),
            data.get("image_data"),
            data.get("image_file"),
        ]
        provided_sources = [source for source in sources if source]

        if len(provided_sources) != 1:
            raise serializers.ValidationError(
                "Exactly one image source must be provided: image_url, image_data, or image_file."
            )

        return data

    def validate_image_data(self, value):
        """Validate base64 image data."""
        if not value:
            return value

        # Remove data URL prefix if present
        if value.startswith("data:image/"):
            try:
                value = value.split(",", 1)[1]
            except IndexError:
                raise serializers.ValidationError("Invalid data URL format.") from None

        # Validate base64 format
        try:
            base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 image data.") from None

        return value

    def validate_image_file(self, value):
        """Validate uploaded face image file."""
        if not value:
            return value

        # Check file size (max 6MB)
        max_size = 6 * 1024 * 1024  # 6MB
        if value.size > max_size:
            raise serializers.ValidationError(
                "Image file too large. Maximum size is 6MB."
            )

        # Check file type
        allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/bmp"]
        if value.content_type not in allowed_types:
            raise serializers.ValidationError(
                f"Unsupported image format. Allowed: {', '.join(allowed_types)}"
            )

        return value


class AddUserFaceResponseSerializer(serializers.Serializer):
    """Serializer for add user face response."""

    user_id = serializers.UUIDField()
    persistedFaceId = serializers.CharField()
    message = serializers.CharField()


class CompleteUserValidationSerializer(serializers.Serializer):
    """
    Serializer for complete user validation endpoint.
    Handles adding user to person group, adding faces, and training.
    """

    user_id = serializers.UUIDField(help_text="UUID of the user to validate")

    person_group_id = serializers.CharField(
        max_length=64, help_text="Person group ID where user will be added"
    )

    images = serializers.ListField(
        child=serializers.CharField(),
        min_length=1,
        max_length=10,
        help_text="List of base64 encoded face images (1-10 images)",
    )

    def validate_images(self, value):
        """Validate list of base64 image data."""
        validated_images = []

        for i, image_data in enumerate(value):
            # Remove data URL prefix if present
            if image_data.startswith("data:image/"):
                try:
                    image_data = image_data.split(",", 1)[1]
                except IndexError:
                    raise serializers.ValidationError(
                        f"Invalid data URL format for image {i+1}."
                    ) from None

            # Validate base64 format
            try:
                base64.b64decode(image_data)
            except Exception as e:
                raise serializers.ValidationError(
                    f"Invalid base64 image data for image {i+1}."
                ) from e

            validated_images.append(image_data)

        return validated_images

    def validate_user_id(self, value):
        """Validate that user exists and is active."""
        from django.contrib.auth import get_user_model

        User = get_user_model()

        try:
            User.objects.get(id=value, is_active=True)
            return value
        except User.DoesNotExist as e:
            raise serializers.ValidationError("User not found or inactive.") from e


class CompleteUserValidationResponseSerializer(serializers.Serializer):
    """Response serializer for complete user validation."""

    user_id = serializers.UUIDField()
    person_group_id = serializers.CharField()
    person_id = serializers.CharField()

    # Operation results
    person_created = serializers.BooleanField()
    images_added = serializers.IntegerField()
    training_initiated = serializers.BooleanField()

    # Detailed results
    face_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Azure Face API persistent face IDs",
    )

    errors = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="List of non-critical errors encountered",
    )  # type: ignore[assignment]

    message = serializers.CharField()
