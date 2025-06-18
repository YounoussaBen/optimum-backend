"""
Django settings initialization for optimum project.
"""

import os

# Set default settings module based on environment
if os.environ.get("DJANGO_SETTINGS_MODULE") is None:
    # Default to development settings
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings.dev")
