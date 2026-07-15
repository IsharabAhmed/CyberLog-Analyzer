"""
Log Management models.

Contains models for uploaded log files and individual parsed log entries,
supporting multiple log formats (Apache, Nginx, SSH, Firewall, Linux Auth).
"""
import uuid

from django.conf import settings
from django.db import models


class LogFile(models.Model):
    """Represents an uploaded log file."""

    LOG_TYPE_CHOICES = [
        ('apache', 'Apache'),
        ('nginx', 'Nginx'),
        ('auth', 'Linux Auth'),
        ('firewall', 'Firewall'),
        ('ssh', 'SSH'),
        ('auto', 'Auto-detect'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='log_files',
    )
    file = models.FileField(upload_to='uploads/logs/%Y/%m/%d/')
    filename = models.CharField(max_length=255)
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES, default='auto')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    total_entries = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, default='')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'Log File'
        verbose_name_plural = 'Log Files'

    def __str__(self):
        return f"{self.filename} ({self.get_log_type_display()})"


class LogEntry(models.Model):
    """Individual parsed log entry."""

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    log_file = models.ForeignKey(LogFile, on_delete=models.CASCADE, related_name='entries')
    timestamp = models.DateTimeField(null=True, blank=True, db_index=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.CharField(max_length=100, default='UNKNOWN')
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='info',
        db_index=True,
    )
    description = models.TextField(default='')
    raw_line = models.TextField()
    line_number = models.IntegerField()
    risk_score = models.FloatField(default=0.0, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp', 'line_number']
        verbose_name = 'Log Entry'
        verbose_name_plural = 'Log Entries'
        indexes = [
            models.Index(fields=['log_file', 'severity']),
            models.Index(fields=['log_file', 'timestamp']),
            models.Index(fields=['source_ip', 'timestamp']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.source_ip or 'N/A'} - {self.action}"

    @property
    def severity_color(self):
        """Return a CSS-friendly color name for the severity level."""
        colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'gray',
        }
        return colors.get(self.severity, 'gray')
