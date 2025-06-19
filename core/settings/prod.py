"""
Django production settings for optimum project.
"""

import os
from datetime import timedelta

import dj_database_url

from .base import *  # noqa: F403, F401

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Production allowed hosts - will be set via environment variables
ALLOWED_HOSTS = (
    os.getenv("ALLOWED_HOSTS", "").split(",")
    if os.getenv("ALLOWED_HOSTS")
    else ["optimum-backend.onrender.com"]
)

# Production database configuration
# For Azure App Service, use the connection string provided by Azure
if "AZURE_POSTGRESQL_CONNECTIONSTRING" in os.environ:
    # Parse Azure connection string
    conn_str = os.environ["AZURE_POSTGRESQL_CONNECTIONSTRING"]
    conn_str_parts = conn_str.split(" ")
    conn_dict = {}
    for part in conn_str_parts:
        if "=" in part:
            key, value = part.split("=", 1)
            conn_dict[key] = value

    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": conn_dict.get("dbname"),
            "USER": conn_dict.get("user"),
            "PASSWORD": conn_dict.get("password"),
            "HOST": conn_dict.get("host"),
            "PORT": conn_dict.get("port", "5432"),
            "OPTIONS": {
                "sslmode": "require",
            },
        }
    }
elif "DATABASE_URL" in os.environ:
    # Parse DATABASE_URL format
    DATABASES = {"default": dj_database_url.parse(os.environ.get("DATABASE_URL"))}
else:
    # Use individual environment variables
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME"),
            "USER": os.getenv("DB_USER"),
            "PASSWORD": os.getenv("DB_PASSWORD"),
            "HOST": os.getenv("DB_HOST"),
            "PORT": os.getenv("DB_PORT", "5432"),
            "OPTIONS": {
                "sslmode": "require",
            },
        }
    }

# Production security settings
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"

# Static files configuration for production
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# Whitenoise configuration
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True

# Production CORS settings
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = (
    os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if os.getenv("CORS_ALLOWED_ORIGINS")
    else []
)

# Production cache configuration (Redis on Azure)
if "AZURE_REDIS_CONNECTIONSTRING" in os.environ:
    redis_url = os.environ["AZURE_REDIS_CONNECTIONSTRING"]
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": redis_url,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "cache_table",
        }
    }

# Session configuration
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# Email configuration for production
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True").lower() == "true"
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "noreply@optimum.com")

# Production logging configuration
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "[{levelname}] {asctime} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# Azure-specific configuration
if "WEBSITE_HOSTNAME" in os.environ:
    # Running on Azure App Service
    ALLOWED_HOSTS.append(os.environ["WEBSITE_HOSTNAME"])

    # Azure Application Insights (if configured)
    if "APPLICATIONINSIGHTS_CONNECTION_STRING" in os.environ:
        INSTALLED_APPS += ["opencensus.ext.django"]
        MIDDLEWARE += ["opencensus.ext.django.middleware.OpencensusMiddleware"]

        OPENCENSUS = {
            "TRACE": {
                "SAMPLER": "opencensus.trace.samplers.ProbabilitySampler(rate=1)",
                "EXPORTER": f"""opencensus.ext.azure.trace_exporter.AzureExporter(
                    connection_string="{os.environ['APPLICATIONINSIGHTS_CONNECTION_STRING']}"
                )""",
            }
        }

# Azure Face API configuration from environment
AZURE_FACE_API_KEY = os.getenv("AZURE_FACE_API_KEY")
AZURE_FACE_ENDPOINT = os.getenv("AZURE_FACE_ENDPOINT")
AZURE_FACE_PERSON_GROUP_ID = os.getenv("AZURE_FACE_PERSON_GROUP_ID")

# File storage configuration (Azure Blob Storage)
if "AZURE_STORAGE_ACCOUNT_NAME" in os.environ:
    DEFAULT_FILE_STORAGE = "storages.backends.azure_storage.AzureStorage"
    AZURE_ACCOUNT_NAME = os.environ["AZURE_STORAGE_ACCOUNT_NAME"]
    AZURE_ACCOUNT_KEY = os.environ.get("AZURE_STORAGE_ACCOUNT_KEY")
    AZURE_CONTAINER = os.environ.get("AZURE_STORAGE_CONTAINER", "media")
    AZURE_CUSTOM_DOMAIN = f"{AZURE_ACCOUNT_NAME}.blob.core.windows.net"
    MEDIA_URL = f"https://{AZURE_CUSTOM_DOMAIN}/{AZURE_CONTAINER}/"

# Production-specific JWT settings
SIMPLE_JWT.update(
    {
        "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),  # Shorter for production
        "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    }
)

# Data upload limits
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB

print("Production mode enabled")
print(f"Allowed hosts: {ALLOWED_HOSTS}")
print(f"Database host: {DATABASES['default'].get('HOST', 'Not configured')}")
print(f"Azure Face API configured: {bool(AZURE_FACE_API_KEY)}")
