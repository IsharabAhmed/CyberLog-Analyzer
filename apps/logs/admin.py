"""Admin configuration for Log Management models."""
from django.contrib import admin

from .models import LogFile, LogEntry


@admin.register(LogFile)
class LogFileAdmin(admin.ModelAdmin):
    """Admin interface for LogFile model."""

    list_display = ['filename', 'log_type', 'status', 'total_entries', 'uploaded_at', 'user']
    list_filter = ['log_type', 'status']
    search_fields = ['filename']
    readonly_fields = ['id', 'uploaded_at', 'processed_at']
    list_per_page = 25


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    """Admin interface for LogEntry model."""

    list_display = ['timestamp', 'source_ip', 'action', 'severity', 'risk_score', 'log_file']
    list_filter = ['severity', 'action']
    search_fields = ['source_ip', 'description', 'raw_line']
    raw_id_fields = ['log_file']
    readonly_fields = ['id']
    list_per_page = 50
