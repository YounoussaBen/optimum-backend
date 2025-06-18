from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

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
        "is_verified",
        "is_active",
        "date_joined",
    ]

    list_filter = [
        "is_active",
        "is_verified",
        "date_joined",
    ]

    search_fields = [
        "email",
        "first_name",
        "last_name",
        "phone_number",
    ]

    ordering = ["-date_joined"]

    # Read-only fields
    readonly_fields = [
        "unique_pin_identifier",
        "date_joined",
        "updated_at",
        "last_login",
    ]

    # Override fieldsets to remove username references
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name", "phone_number")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_verified",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )

    # Override add_fieldsets for creating new users
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )
