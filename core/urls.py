# core/urls.py
"""
URL configuration for optimum project.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path
from drf_yasg import openapi
from drf_yasg.generators import OpenAPISchemaGenerator
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework.routers import DefaultRouter

# Create a router for API endpoints
router = DefaultRouter()


class BothHttpAndHttpsSchemaGenerator(OpenAPISchemaGenerator):
    def get_schema(self, request=None, public=False):
        schema = super().get_schema(request, public)
        schema.schemes = ["http", "https"]
        return schema


schema_view = get_schema_view(
    openapi.Info(
        title="Optimum Financial API",
        default_version="v1",
        description="Financial application with face authentication",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@optimum.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.IsAuthenticated],
    generator_class=BothHttpAndHttpsSchemaGenerator,
)


def api_root(request):
    """Modern API root endpoint with template"""
    return render(request, "index.html")


urlpatterns = [
    # Root endpoint
    path("", api_root, name="api_root"),
    # Swagger/OpenAPI endpoints
    re_path(
        r"^swagger(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    re_path(
        r"^swagger/$",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    re_path(
        r"^redoc/$",
        schema_view.with_ui("redoc", cache_timeout=0),
        name="schema-redoc",
    ),
    # Admin
    path("admin/", admin.site.urls),
    # API endpoints
    path("api/", include("apps.users.urls")),
    path("api/", include("apps.face_auth.urls")),
    path("api/", include("apps.proof_of_life.urls")),
    path("api/", include(router.urls)),
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
