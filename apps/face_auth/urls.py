"""
URL patterns for Face Authentication API.
Provides RESTful endpoints for Azure Face API integration.
"""

from django.urls import path

from .views import (
    AddUserFaceView,
    AddUserToPersonGroupView,
    FaceAuthenticationView,
    FaceVerificationView,
    PersonGroupCreateView,
    PersonGroupDeleteView,
    PersonGroupInfoView,
    PersonGroupListView,
    PersonGroupTrainingStatusView,
    PersonGroupTrainView,
)

app_name = "face_auth"

urlpatterns = [
    # Authentication endpoints (public/user access)
    path("auth/face-login/", FaceAuthenticationView.as_view(), name="face-login"),
    path("auth/verify/", FaceVerificationView.as_view(), name="face-verify"),
    # Person Group Management (Admin only)
    path(
        "admin/person-groups/", PersonGroupListView.as_view(), name="person-group-list"
    ),
    path(
        "admin/person-groups/create/",
        PersonGroupCreateView.as_view(),
        name="person-group-create",
    ),
    path(
        "admin/person-groups/info/",
        PersonGroupInfoView.as_view(),
        name="person-group-info",
    ),
    path(
        "admin/person-groups/delete/",
        PersonGroupDeleteView.as_view(),
        name="person-group-delete",
    ),
    path(
        "admin/person-groups/train/",
        PersonGroupTrainView.as_view(),
        name="person-group-train",
    ),
    path(
        "admin/person-groups/training-status/",
        PersonGroupTrainingStatusView.as_view(),
        name="person-group-training-status",
    ),
    # User Management (Admin only)
    path(
        "users/add-to-group/",
        AddUserToPersonGroupView.as_view(),
        name="user-add-to-group",
    ),
    path("users/add-face/", AddUserFaceView.as_view(), name="user-add-face"),
]
