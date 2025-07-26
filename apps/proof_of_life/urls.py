from django.urls import path

from . import views

# App namespace
app_name = "proof_of_life"

patterns = [
    # User-facing proof of life endpoints
    path(
        "proof-of-life/status/",
        views.ProofOfLifeStatusView.as_view(),
        name="status",
    ),
    # Two-step verification process
    path(
        "proof-of-life/verify/",
        views.ProofOfLifeVerificationView.as_view(),
        name="verification",  # Step 1: Face verification
    ),
    path(
        "proof-of-life/otp/generate/",
        views.ProofOfLifeOTPGenerateView.as_view(),
        name="otp_generate",  # Step 2A: Generate OTP
    ),
    path(
        "proof-of-life/otp/verify/",
        views.ProofOfLifeOTPVerifyView.as_view(),
        name="otp_verify",  # Step 2B: Verify OTP and complete
    ),
    path(
        "proof-of-life/history/",
        views.ProofOfLifeHistoryView.as_view(),
        name="history",
    ),
    # Admin endpoints
    path(
        "admin/proof-of-life/verifications/",
        views.ProofOfLifeAdminView.as_view(),
        name="admin",
    ),
]

urlpatterns = patterns
