"""
Django development settings for optimum project.
"""

from datetime import timedelta

from .base import *  # noqa: F403, F401

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Development-specific allowed hosts
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

# Database for development
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': env('DB_NAME', default='optimum_dev'),
#         'USER': env('DB_USER', default='postgres'),
#         'PASSWORD': env('DB_PASSWORD', default='postgres'),
#         'HOST': env('DB_HOST', default='localhost'),
#         'PORT': env('DB_PORT', default='5432'),
#     }
# }

# Add debug toolbar for development
INSTALLED_APPS += [
    "debug_toolbar",
]

MIDDLEWARE += [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
]

# Debug toolbar configuration
INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
]

# Email backend for development
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Static files serving in development
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True

# Cache configuration for development
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}

# Disable CSRF for development API testing
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# Development logging - more verbose
# Modify LOGGING directly (imported from base)
# Use a safe way to modify the existing LOGGING dict
_logging_config = globals().get("LOGGING", {})
if _logging_config and "handlers" in _logging_config:
    _logging_config["handlers"]["console"]["level"] = "DEBUG"
    _logging_config["loggers"]["apps"]["level"] = "DEBUG"
    _logging_config["loggers"]["django"]["level"] = "DEBUG"

# Security settings - relaxed for development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False

# JWT settings for development (longer lifetime)
SIMPLE_JWT.update(
    {
        "ACCESS_TOKEN_LIFETIME": timedelta(hours=24),  # Longer for development
        "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    }
)

# Development-specific environment variables
# Get the variables from base settings first
azure_face_api_key = globals().get("AZURE_FACE_API_KEY", "")
azure_face_endpoint = globals().get("AZURE_FACE_ENDPOINT", "")

if not azure_face_api_key:
    AZURE_FACE_API_KEY = "4nsYyv6RsLcdcwi9EpjwrN5HAR8GojsDpQPpFH83P4pEESYslq6EJQQJ99BCACYeBjFXJ3w3AAAKACOGHMcX"
else:
    AZURE_FACE_API_KEY = azure_face_api_key

if not azure_face_endpoint:
    AZURE_FACE_ENDPOINT = "https://eastus.api.cognitive.microsoft.com/face/v1.0/"
else:
    AZURE_FACE_ENDPOINT = azure_face_endpoint

# Print configuration for debugging
print(f"DEBUG: {DEBUG}")
print(f"Database: {DATABASES['default']['NAME']}")
print(f"Azure Face API configured: {bool(AZURE_FACE_API_KEY)}")
