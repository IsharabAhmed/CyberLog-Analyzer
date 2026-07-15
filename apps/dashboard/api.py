"""
JSON API endpoints for the dashboard charts and statistics.

All endpoints return JsonResponse data formatted for Chart.js consumption.
Each endpoint requires authentication and scopes data to the requesting user's
log files only.

Endpoints:
    - api_threat_timeline: Time-series alert data grouped by date and severity
    - api_severity_distribution: Event counts by severity level
    - api_top_attackers: Top 10 source IPs by alert count
    - api_geo_attacks: Geographic attack data with approximate coordinates
    - api_stats: Summary statistics for the dashboard header
"""

import hashlib
import math
from collections import defaultdict
from datetime import timedelta

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Avg, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.analytics.models import Alert


@login_required
def api_threat_timeline(request):
    """
    Return threat timeline data grouped by date and severity.

    Query Parameters:
        days (int): Number of days to include (default: 30).

    Returns:
        JSON with:
            - labels: List of date strings (YYYY-MM-DD)
            - datasets: List of dicts with label, data, and borderColor per severity
    """
    try:
        days = int(request.GET.get('days', 30))
        days = min(max(days, 1), 365)  # Clamp between 1 and 365
    except (ValueError, TypeError):
        days = 30

    user = request.user
    start_date = timezone.now() - timedelta(days=days)

    try:
        alerts = Alert.objects.filter(
            log_file__user=user,
            created_at__gte=start_date,
        ).annotate(
            date=TruncDate('created_at')
        ).values('date', 'severity').annotate(
            count=Count('id')
        ).order_by('date')

        # Build date labels for every day in the range
        date_labels = []
        current_date = start_date.date()
        end_date = timezone.now().date()
        while current_date <= end_date:
            date_labels.append(current_date.strftime('%Y-%m-%d'))
            current_date += timedelta(days=1)

        # Initialize severity data with zeros
        severity_levels = ['critical', 'high', 'medium', 'low']
        severity_data = {s: {d: 0 for d in date_labels} for s in severity_levels}

        # Fill in actual counts
        for entry in alerts:
            date_str = entry['date'].strftime('%Y-%m-%d')
            sev = entry['severity']
            if sev in severity_data and date_str in severity_data[sev]:
                severity_data[sev][date_str] = entry['count']

        severity_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#eab308',
            'low': '#3b82f6',
        }

        datasets = []
        for severity in severity_levels:
            datasets.append({
                'label': severity.capitalize(),
                'data': [severity_data[severity][d] for d in date_labels],
                'borderColor': severity_colors[severity],
                'backgroundColor': severity_colors[severity] + '33',
                'fill': True,
            })

        return JsonResponse({
            'labels': date_labels,
            'datasets': datasets,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_severity_distribution(request):
    """
    Return event counts grouped by severity level.

    Returns:
        JSON with:
            - labels: List of severity names
            - data: List of counts
            - colors: List of hex color strings
    """
    user = request.user

    try:
        severity_levels = ['critical', 'high', 'medium', 'low', 'info']
        severity_colors = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280']

        entries = LogEntry.objects.filter(log_file__user=user)
        counts = []
        for severity in severity_levels:
            counts.append(entries.filter(severity=severity).count())

        return JsonResponse({
            'labels': [s.capitalize() for s in severity_levels],
            'data': counts,
            'colors': severity_colors,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_top_attackers(request):
    """
    Return the top 10 source IPs by alert count.

    Returns:
        JSON with:
            - labels: List of IP address strings
            - data: List of alert counts
            - details: List of dicts with ip, alert_count, and top severity
    """
    user = request.user

    try:
        top_ips = (
            Alert.objects.filter(log_file__user=user)
            .exclude(source_ip__isnull=True)
            .values('source_ip')
            .annotate(alert_count=Count('id'))
            .order_by('-alert_count')[:10]
        )

        labels = []
        data = []
        details = []

        for entry in top_ips:
            ip = str(entry['source_ip'])
            count = entry['alert_count']
            labels.append(ip)
            data.append(count)

            # Determine the highest severity alert for this IP
            top_severity = (
                Alert.objects.filter(
                    log_file__user=user,
                    source_ip=entry['source_ip'],
                )
                .values('severity')
                .annotate(count=Count('id'))
                .order_by('-count')
                .first()
            )
            severity = top_severity['severity'] if top_severity else 'low'

            details.append({
                'ip': ip,
                'alert_count': count,
                'severity': severity,
            })

        return JsonResponse({
            'labels': labels,
            'data': data,
            'details': details,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def _ip_to_geo(ip_str):
    """
    Generate approximate geographic coordinates from an IP address.

    For demo purposes (no GeoIP database bundled):
        - Private IP ranges (10.x, 172.16-31.x, 192.168.x) -> 'Local Network'
          with fixed coordinates (37.7749, -122.4194 — San Francisco)
        - Public IPs -> deterministic lat/lng derived from IP hash

    Args:
        ip_str: IP address string.

    Returns:
        Dict with lat, lng, and label.
    """
    # Check for private IP ranges
    private_ranges = [
        ('10.', 'Local Network'),
        ('172.16.', 'Local Network'),
        ('172.17.', 'Local Network'),
        ('172.18.', 'Local Network'),
        ('172.19.', 'Local Network'),
        ('172.20.', 'Local Network'),
        ('172.21.', 'Local Network'),
        ('172.22.', 'Local Network'),
        ('172.23.', 'Local Network'),
        ('172.24.', 'Local Network'),
        ('172.25.', 'Local Network'),
        ('172.26.', 'Local Network'),
        ('172.27.', 'Local Network'),
        ('172.28.', 'Local Network'),
        ('172.29.', 'Local Network'),
        ('172.30.', 'Local Network'),
        ('172.31.', 'Local Network'),
        ('192.168.', 'Local Network'),
        ('127.', 'Localhost'),
        ('0.0.0.0', 'Unknown'),
    ]

    for prefix, label in private_ranges:
        if ip_str.startswith(prefix):
            return {
                'lat': 37.7749,
                'lng': -122.4194,
                'label': label,
            }

    # Generate deterministic coordinates from IP hash
    ip_hash = hashlib.md5(ip_str.encode()).hexdigest()
    # Use different portions of the hash for lat and lng
    lat_raw = int(ip_hash[:8], 16) / 0xFFFFFFFF  # 0.0 to 1.0
    lng_raw = int(ip_hash[8:16], 16) / 0xFFFFFFFF  # 0.0 to 1.0

    # Map to realistic latitude (-60 to 70) and longitude (-160 to 160) ranges
    lat = (lat_raw * 130) - 60
    lng = (lng_raw * 320) - 160

    # Generate a plausible region label from the hash
    regions = [
        'Eastern Europe', 'Western Europe', 'East Asia',
        'Southeast Asia', 'North America', 'South America',
        'Central Asia', 'Middle East', 'Northern Africa',
        'Sub-Saharan Africa', 'Oceania', 'Nordic Region',
        'Southern Europe', 'Caribbean', 'Central America',
        'South Asia',
    ]
    region_idx = int(ip_hash[16:18], 16) % len(regions)

    return {
        'lat': round(lat, 4),
        'lng': round(lng, 4),
        'label': regions[region_idx],
    }


@login_required
def api_geo_attacks(request):
    """
    Return geographic attack data with approximate coordinates.

    Uses IP address hashing for approximate geolocation since no GeoIP
    database is bundled. Private IPs are mapped to 'Local Network'.

    Returns:
        JSON with:
            - locations: List of dicts with ip, lat, lng, count, and label
    """
    user = request.user

    try:
        attack_ips = (
            Alert.objects.filter(log_file__user=user)
            .exclude(source_ip__isnull=True)
            .values('source_ip')
            .annotate(count=Count('id'))
            .order_by('-count')[:50]
        )

        locations = []
        for entry in attack_ips:
            ip = str(entry['source_ip'])
            geo = _ip_to_geo(ip)
            locations.append({
                'ip': ip,
                'lat': geo['lat'],
                'lng': geo['lng'],
                'count': entry['count'],
                'label': geo['label'],
            })

        return JsonResponse({'locations': locations})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_stats(request):
    """
    Return summary statistics for the dashboard.

    Returns:
        JSON with:
            - total_events: Total log entries for the user
            - total_alerts: Total alerts for the user
            - total_files: Total uploaded log files
            - critical_count: Count of unresolved critical alerts
            - avg_risk_score: Average risk score across all log entries
            - events_today: Log entries with timestamps from today
            - alerts_today: Alerts created today
    """
    user = request.user

    try:
        today = timezone.now().date()

        user_entries = LogEntry.objects.filter(log_file__user=user)
        user_alerts = Alert.objects.filter(log_file__user=user)

        total_events = user_entries.count()
        total_alerts = user_alerts.count()
        total_files = user.log_files.count()
        critical_count = user_alerts.filter(
            severity='critical', is_resolved=False
        ).count()

        avg_risk = user_entries.aggregate(avg=Avg('risk_score'))['avg']
        avg_risk_score = round(avg_risk, 2) if avg_risk is not None else 0.0

        events_today = user_entries.filter(timestamp__date=today).count()
        alerts_today = user_alerts.filter(created_at__date=today).count()

        return JsonResponse({
            'total_events': total_events,
            'total_alerts': total_alerts,
            'total_files': total_files,
            'critical_count': critical_count,
            'avg_risk_score': avg_risk_score,
            'events_today': events_today,
            'alerts_today': alerts_today,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
