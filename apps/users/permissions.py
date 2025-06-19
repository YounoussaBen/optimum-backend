from rest_framework.permissions import BasePermission


class IsAdminUser(BasePermission):
    """
    Permission to only allow admin users (staff/superuser) to access the view.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated and is staff/superuser."""
        return bool(
            request.user
            and request.user.is_authenticated
            and (request.user.is_staff or request.user.is_superuser)
        )

    def has_object_permission(self, request, view, obj):
        """Check object-level permissions for admin users."""
        return self.has_permission(request, view)


class IsOwnerOrAdmin(BasePermission):
    """
    Permission to allow users to access their own data, or admin users to access any data.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated."""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        """
        Check if user is the owner of the object or is an admin.
        """
        # Admin users can access any object
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Users can only access their own data
        return obj == request.user


class IsOwnerReadOnly(BasePermission):
    """
    Permission to allow users to read their own data only.
    No write permissions for normal users.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated."""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        """
        Users can only read their own data.
        No write permissions for normal users (as per requirements).
        """
        # Admin users can do anything
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Normal users can only read their own data
        if obj == request.user:
            return request.method in ["GET", "HEAD", "OPTIONS"]

        return False


class IsSelfProfile(BasePermission):
    """
    Permission for users to access only their own profile.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated."""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        """Users can only access their own profile."""
        return obj == request.user


class IsVerifiedUser(BasePermission):
    """
    Permission to only allow verified users to access the view.
    Used for sensitive operations.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated and verified."""
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "is_verified", False)
        )


class IsFaceRegisteredUser(BasePermission):
    """
    Permission to only allow users who have completed face registration.
    Used for face-based authentication operations.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated and has face registered."""
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "is_face_registered", False)
        )


class IsActiveUser(BasePermission):
    """
    Permission to only allow active users.
    """

    def has_permission(self, request, view):
        """Check if user is authenticated and active."""
        return bool(
            request.user and request.user.is_authenticated and request.user.is_active
        )
