"""Analytics app configuration."""
from django.apps import AppConfig


class AnalyticsConfig(AppConfig):
    """Configuration for the Security Analytics app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.analytics'
    verbose_name = 'Security Analytics'
