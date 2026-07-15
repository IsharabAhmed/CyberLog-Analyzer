"""Logs app configuration."""
from django.apps import AppConfig


class LogsConfig(AppConfig):
    """Configuration for the Log Management app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.logs'
    verbose_name = 'Log Management'
