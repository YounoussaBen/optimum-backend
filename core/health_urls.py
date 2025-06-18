"""
Health check URLs for optimum project.
"""

import logging

from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.urls import path

logger = logging.getLogger(__name__)


def health_check(request):
    """Basic health check endpoint."""
    try:
        # Test database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        # Check if Azure Face API is configured
        face_api_configured = bool(
            settings.AZURE_FACE_API_KEY and settings.AZURE_FACE_ENDPOINT
        )

        return JsonResponse(
            {
                "status": "healthy",
                "database": "connected",
                "azure_face_api": (
                    "configured" if face_api_configured else "not_configured"
                ),
                "debug": settings.DEBUG,
            }
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JsonResponse({"status": "unhealthy", "error": str(e)}, status=500)


def readiness_check(request):
    """Readiness check for Azure App Service."""
    try:
        # More comprehensive checks for production readiness
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM django_migrations")
            migration_count = cursor.fetchone()[0]

        checks = {
            "database_migrations": migration_count > 0,
            "azure_face_api": bool(settings.AZURE_FACE_API_KEY),
            "secret_key": bool(settings.SECRET_KEY),
        }

        all_ready = all(checks.values())

        return JsonResponse(
            {
                "status": "ready" if all_ready else "not_ready",
                "checks": checks,
            },
            status=200 if all_ready else 503,
        )
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JsonResponse({"status": "not_ready", "error": str(e)}, status=503)


urlpatterns = [
    path("", health_check, name="health"),
    path("ready/", readiness_check, name="readiness"),
]
