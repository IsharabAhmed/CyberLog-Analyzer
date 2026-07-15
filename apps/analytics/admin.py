"""Admin configuration for Security Analytics models."""
from django.contrib import admin

from .models import Alert, ThreatSummary


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """Admin interface for Alert model."""

    list_display = [
        'title', 'alert_type', 'severity', 'source_ip',
        'confidence', 'is_resolved', 'created_at',
    ]
    list_filter = ['alert_type', 'severity', 'is_resolved']
    search_fields = ['title', 'description', 'source_ip']
    readonly_fields = ['id', 'created_at']
    list_per_page = 25


@admin.register(ThreatSummary)
class ThreatSummaryAdmin(admin.ModelAdmin):
    """Admin interface for ThreatSummary model."""

    list_display = ['log_file', 'total_events', 'total_alerts', 'risk_score_avg', 'created_at']
    readonly_fields = ['id', 'created_at']
    list_per_page = 25
