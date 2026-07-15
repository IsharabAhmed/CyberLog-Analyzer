"""
Development-specific Django settings.

Uses SQLite and console email backend for local development.
"""
from .base import *  # noqa: F401, F403

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Database - SQLite for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Email - console backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
