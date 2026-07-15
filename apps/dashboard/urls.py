"""
URL configuration for the dashboard app.

Routes:
    /                           - Dashboard overview
    /reports/                   - Report generation page
    /reports/download/          - Download generated report (CSV/PDF)
    /api/threat-timeline/       - JSON: Threat timeline data
    /api/severity-distribution/ - JSON: Severity distribution data
    /api/top-attackers/         - JSON: Top attacking IPs
    /api/geo-attacks/           - JSON: Geographic attack data
    /api/stats/                 - JSON: Summary statistics
"""

from django.urls import path

from .views import dashboard_view, reports_view, report_download_view
from .api import (
    api_threat_timeline,
    api_severity_distribution,
    api_top_attackers,
    api_geo_attacks,
    api_stats,
)

app_name = 'dashboard'

urlpatterns = [
    path('', dashboard_view, name='overview'),
    path('reports/', reports_view, name='reports'),
    path('reports/download/', report_download_view, name='report-download'),
    # API endpoints for dashboard charts
    path('api/threat-timeline/', api_threat_timeline, name='api-threat-timeline'),
    path('api/severity-distribution/', api_severity_distribution, name='api-severity-distribution'),
    path('api/top-attackers/', api_top_attackers, name='api-top-attackers'),
    path('api/geo-attacks/', api_geo_attacks, name='api-geo-attacks'),
    path('api/stats/', api_stats, name='api-stats'),
]
