from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Simple custom admin for User model."""

    # List view configuration
    list_display = [
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "profile_picture_thumbnail",
        "is_verified",
        "is_active",
        "face_status",
        "date_joined",
    ]

    list_filter = [
        "is_active",
        "is_verified",
        "face_added",
        "gender",
        "nationality",
        "date_joined",
    ]

    search_fields = [
        "email",
        "first_name",
        "middle_name",
        "last_name",
        "phone_number",
        "unique_pin_identifier",
        "nationality",
    ]

    ordering = ["-date_joined"]

    # Read-only fields
    readonly_fields = [
        "unique_pin_identifier",
        "person_id",
        "face_added",
        "auth_faces_count",
        "profile_picture",
        "profile_picture_display",
        "date_joined",
        "updated_at",
        "last_login",
    ]

    # Override fieldsets to remove username references
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Information",
            {
                "fields": (
                    "first_name",
                    "middle_name",
                    "last_name",
                    "phone_number",
                    "date_of_birth",
                    "nationality",
                    "gender",
                )
            },
        ),
        (
            "Profile Picture",
            {
                "fields": ("profile_picture", "profile_picture_display"),
                "description": "Profile picture is managed via API uploads. URL is read-only.",
            },
        ),
        (
            "Face Recognition",
            {
                "fields": (
                    "person_id",
                    "face_added",
                    "auth_faces_count",
                    "unique_pin_identifier",
                ),
                "description": "Face recognition data managed by Azure Face API.",
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_verified",
                    "verification_expires_at",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            "Important Dates",
            {
                "fields": ("last_login", "date_joined", "updated_at"),
            },
        ),
        (
            "Advanced",
            {
                "classes": ("collapse",),
                "fields": ("external_data",),
                "description": "External API data storage (JSON format).",
            },
        ),
    )

    # Override add_fieldsets for creating new users
    add_fieldsets = (
        (
            "Account Information",
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
        (
            "Personal Information",
            {
                "classes": ("wide",),
                "fields": (
                    "first_name",
                    "middle_name",
                    "last_name",
                    "phone_number",
                    "date_of_birth",
                    "nationality",
                    "gender",
                ),
            },
        ),
        (
            "Permissions",
            {
                "fields": ("is_active", "is_staff", "is_superuser"),
            },
        ),
    )

    def profile_picture_thumbnail(self, obj):
        """Display profile picture thumbnail in list view."""
        if obj.profile_picture:
            return format_html(
                '<img src="{}" style="width: 50px; height: 50px; object-fit: cover; border-radius: 25px;" />',
                obj.profile_picture,
            )
        return "No Image"

    profile_picture_thumbnail.short_description = "Profile Picture"  # type: ignore[attr-defined]

    def profile_picture_display(self, obj):
        """Display profile picture in detail view."""
        if obj.profile_picture:
            return format_html(
                """
                <div>
                    <img src="{}" style="max-width: 200px; max-height: 200px; object-fit: cover; border-radius: 10px;" />
                    <br><br>
                    <a href="{}" target="_blank">View Full Size</a>
                </div>
                """,
                obj.profile_picture,
                obj.profile_picture,
            )
        return "No profile picture uploaded"

    profile_picture_display.short_description = "Profile Picture Preview"  # type: ignore[attr-defined]

    def face_status(self, obj):
        """Display face registration status."""
        if obj.is_face_registered:
            return format_html('<span style="color: green;">Registered</span>')
        elif obj.face_added:
            return format_html('<span style="color: orange;">Pending</span>')
        return format_html('<span style="color: red;">Not Registered</span>')

    face_status.short_description = "Face Status"  # type: ignore[attr-defined]
