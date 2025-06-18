"""
URL configuration for optimum project.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.routers import DefaultRouter


class ProtectedSwaggerView(SpectacularSwaggerView):
    permission_classes = [IsAuthenticated]


class ProtectedRedocView(SpectacularRedocView):
    permission_classes = [IsAuthenticated]


# Create a router for API endpoints
router = DefaultRouter()

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # API endpoints
    # path('api/', include('apps.users.urls')),
    # path('api/', include('apps.face_auth.urls')),
    # DRF router
    path("api/", include(router.urls)),
    # API documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        ProtectedSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path("api/redoc/", ProtectedRedocView.as_view(url_name="schema"), name="redoc"),
    # Health check endpoint
    path("health/", include("core.health_urls")),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

    # Debug toolbar
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [
            path("__debug__/", include(debug_toolbar.urls)),
        ] + urlpatterns

# Custom admin configuration
admin.site.site_header = "Optimum Financial Administration"
admin.site.site_title = "Optimum Admin"
admin.site.index_title = "Welcome to Optimum Financial Administration"
