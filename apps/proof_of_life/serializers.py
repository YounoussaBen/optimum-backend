from decimal import Decimal

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import ProofOfLifeAuditLog, ProofOfLifeSettings, ProofOfLifeVerification

User = get_user_model()


class DeviceInfoSerializer(serializers.Serializer):
    """Serializer for device information in verification requests."""

    device_id = serializers.CharField(max_length=255)
    platform = serializers.ChoiceField(choices=["android", "ios", "web"])
    app_version = serializers.CharField(max_length=50)
    os_version = serializers.CharField(max_length=50)


class ProofOfLifeStatusResponseSerializer(serializers.Serializer):
    """Serializer for proof of life status responses."""

    success = serializers.BooleanField()
    message = serializers.CharField()
    status = serializers.ChoiceField(
        choices=[
            ("current", "Current"),
            ("due_soon", "Due Soon"),
            ("overdue", "Overdue"),
            ("blocked", "Blocked"),
        ]
    )
    next_due_date = serializers.DateTimeField(allow_null=True)
    last_verification_date = serializers.DateTimeField(allow_null=True)
    days_until_due = serializers.IntegerField()
    is_overdue = serializers.BooleanField()
    grace_period_days = serializers.IntegerField()


class ProofOfLifeVerificationRequestSerializer(serializers.Serializer):
    """Serializer for proof of life verification requests."""

    confidence_score = serializers.DecimalField(
        max_digits=4,
        decimal_places=3,
        min_value=Decimal("0.000"),
        max_value=Decimal("1.000"),
    )
    liveness_score = serializers.DecimalField(
        max_digits=4,
        decimal_places=3,
        min_value=Decimal("0.000"),
        max_value=Decimal("1.000"),
    )
    device_info = DeviceInfoSerializer()


class ProofOfLifeVerificationResponseSerializer(serializers.Serializer):
    """Serializer for proof of life verification responses."""

    success = serializers.BooleanField()
    message = serializers.CharField()
    verification_id = serializers.CharField()
    next_due_date = serializers.DateTimeField()
    verification_accepted = serializers.BooleanField()
    minimum_confidence_met = serializers.BooleanField()
    minimum_liveness_met = serializers.BooleanField()


class ProofOfLifeRecordSerializer(serializers.ModelSerializer):
    """Serializer for individual proof of life records."""

    verification_id = serializers.CharField()
    verification_date = serializers.DateTimeField()
    confidence_score = serializers.DecimalField(max_digits=4, decimal_places=3)
    liveness_score = serializers.DecimalField(max_digits=4, decimal_places=3)
    status = serializers.CharField()
    device_platform = serializers.CharField()

    class Meta:
        model = ProofOfLifeVerification
        fields = [
            "verification_id",
            "verification_date",
            "confidence_score",
            "liveness_score",
            "status",
            "device_platform",
        ]


class ProofOfLifeHistoryResponseSerializer(serializers.Serializer):
    """Serializer for proof of life history responses."""

    success = serializers.BooleanField()
    message = serializers.CharField()
    records = ProofOfLifeRecordSerializer(many=True)
    total = serializers.IntegerField()
    has_more = serializers.BooleanField()


class ProofOfLifeErrorResponseSerializer(serializers.Serializer):
    """Serializer for error responses."""

    success = serializers.BooleanField(default=False)
    message = serializers.CharField()
    error_code = serializers.CharField(required=False, allow_null=True)
    requires_verification = serializers.BooleanField(required=False, allow_null=True)


class ProofOfLifeVerificationModelSerializer(serializers.ModelSerializer):
    """Full model serializer for proof of life verifications."""

    user_name = serializers.CharField(source="user.get_full_name", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)
    days_until_due = serializers.IntegerField(read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)
    urgency_level = serializers.IntegerField(read_only=True)
    is_verification_successful = serializers.BooleanField(read_only=True)

    class Meta:
        model = ProofOfLifeVerification
        fields = [
            "id",
            "verification_id",
            "user",
            "user_name",
            "user_email",
            "confidence_score",
            "liveness_score",
            "verification_date",
            "next_due_date",
            "device_id",
            "device_platform",
            "app_version",
            "os_version",
            "status",
            "days_until_due",
            "is_overdue",
            "urgency_level",
            "is_verification_successful",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "verification_id",
            "next_due_date",
            "created_at",
            "updated_at",
        ]


class ProofOfLifeSettingsSerializer(serializers.ModelSerializer):
    """Serializer for proof of life settings."""

    updated_by_name = serializers.CharField(
        source="updated_by.get_full_name", read_only=True
    )

    class Meta:
        model = ProofOfLifeSettings
        fields = [
            "id",
            "minimum_confidence_score",
            "minimum_liveness_score",
            "verification_interval_days",
            "grace_period_days",
            "first_reminder_days",
            "urgent_reminder_days",
            "updated_by",
            "updated_by_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class ProofOfLifeAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for proof of life audit logs."""

    user_name = serializers.CharField(source="user.get_full_name", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = ProofOfLifeAuditLog
        fields = [
            "id",
            "user",
            "user_name",
            "user_email",
            "verification",
            "action",
            "description",
            "metadata",
            "ip_address",
            "user_agent",
            "timestamp",
        ]
        read_only_fields = ["id", "timestamp"]
