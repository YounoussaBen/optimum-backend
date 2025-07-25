from django.urls import path

from . import views
from .admin_auth_views import AdminLoginView, AdminLogoutView, TokenRefreshView
from .otp_views import GenerateOTPView, VerifyOTPView

# App namespace
app_name = "users"

patterns = [
    # Admin user management endpoints
    path("users/", views.UserListView.as_view(), name="user-list"),
    path("users/create/", views.UserCreateView.as_view(), name="user-create"),
    path("users/<uuid:id>/", views.UserDetailView.as_view(), name="user-detail"),
    path("users/<uuid:id>/update/", views.UserUpdateView.as_view(), name="user-update"),
    path("users/<uuid:id>/delete/", views.UserDeleteView.as_view(), name="user-delete"),
    # Utility endpoints
    path("users/by-pin/<str:pin>/", views.UserByPinView.as_view(), name="user-by-pin"),
    # User profile endpoint
    path("profile/", views.UserProfileView.as_view(), name="user-profile"),
    path("admin/login/", AdminLoginView.as_view(), name="admin-login"),
    path("admin/logout/", AdminLogoutView.as_view(), name="admin-logout"),
    path("admin/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path(
        "admin/dashboard/", views.DashboardStatsView.as_view(), name="dashboard-stats"
    ),
    path(
        "admin/verify-user/",
        views.AdminUserVerificationView.as_view(),
        name="admin-verify-user",
    ),
    path(
        "admin/adaptive-learning-stats/",
        views.AdaptiveLearningStatsView.as_view(),
        name="adaptive-learning-stats",
    ),
    # Bulk user import endpoint
    path(
        "admin/bulk-import/",
        views.BulkUserImportView.as_view(),
        name="bulk-user-import",
    ),
    # OTP Authentication endpoints
    path("auth/generate-otp/", GenerateOTPView.as_view(), name="generate-otp"),
    path("auth/verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
]

urlpatterns = patterns
