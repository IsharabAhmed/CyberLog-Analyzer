"""
Views for security alert management.

Provides alert listing with filtering/sorting/pagination, and an AJAX endpoint
to toggle the resolved status of individual alerts. All views enforce ownership
— users can only access alerts from their own uploaded log files.
"""

import json

from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.http import require_POST
from django.shortcuts import render

from apps.analytics.models import Alert


@login_required
def alert_list_view(request):
    """
    List all alerts for the current user's log files.

    Supports:
        - Severity filter: ?severity= filters by severity level
        - Alert type filter: ?alert_type= filters by alert type
        - Resolved filter: ?resolved=true/false filters by resolution status
        - Sorting: ?sort= sorts by created_at, severity, or confidence
          (default: -created_at, descending)
        - Pagination: 25 alerts per page, ?page= to navigate

    Context includes counts by severity for summary display.
    """
    user = request.user

    try:
        alerts = Alert.objects.filter(
            log_file__user=user
        ).select_related('log_file', 'log_entry').order_by('-created_at')

        # Severity filter
        severity = request.GET.get('severity', '').strip()
        if severity:
            alerts = alerts.filter(severity=severity)

        # Alert type filter
        alert_type = request.GET.get('alert_type', '').strip()
        if alert_type:
            alerts = alerts.filter(alert_type=alert_type)

        # Resolved filter
        resolved = request.GET.get('resolved', '').strip().lower()
        if resolved == 'true':
            alerts = alerts.filter(is_resolved=True)
        elif resolved == 'false':
            alerts = alerts.filter(is_resolved=False)

        # Sorting
        sort_field = request.GET.get('sort', '-created_at').strip()
        valid_sort_fields = {
            'created_at': 'created_at',
            '-created_at': '-created_at',
            'severity': 'severity',
            '-severity': '-severity',
            'confidence': 'confidence',
            '-confidence': '-confidence',
        }
        sort_by = valid_sort_fields.get(sort_field, '-created_at')
        alerts = alerts.order_by(sort_by)

        # Severity counts (on unfiltered user alerts for overview)
        all_user_alerts = Alert.objects.filter(log_file__user=user)
        severity_counts = {
            'critical': all_user_alerts.filter(severity='critical').count(),
            'high': all_user_alerts.filter(severity='high').count(),
            'medium': all_user_alerts.filter(severity='medium').count(),
            'low': all_user_alerts.filter(severity='low').count(),
        }

        total_count = alerts.count()

        # Paginate results
        paginator = Paginator(alerts, 25)
        page = request.GET.get('page', 1)
        try:
            alerts_page = paginator.page(page)
        except PageNotAnInteger:
            alerts_page = paginator.page(1)
        except EmptyPage:
            alerts_page = paginator.page(paginator.num_pages)

    except Exception as e:
        messages.error(request, f'Error loading alerts: {str(e)}')
        alerts_page = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_count = 0
        severity = ''
        alert_type = ''
        resolved = ''
        sort_field = '-created_at'

    context = {
        'alerts': alerts_page,
        'severity_counts': severity_counts,
        'total_count': total_count,
        'severity': severity,
        'alert_type': alert_type,
        'resolved': resolved,
        'sort': sort_field,
    }

    return render(request, 'analytics/alerts.html', context)


@login_required
@require_POST
def alert_resolve_view(request, pk):
    """
    Toggle the resolved status of an alert.

    Only the owner of the related log file can resolve/unresolve alerts.
    Returns a JSON response indicating success and the new resolved status.

    Args:
        pk: UUID primary key of the Alert.

    Returns:
        JsonResponse with {success: bool, is_resolved: bool} or error.
    """
    alert = get_object_or_404(Alert, pk=pk)

    # Verify ownership
    if alert.log_file.user != request.user:
        return JsonResponse(
            {'success': False, 'error': 'Permission denied.'},
            status=403,
        )

    try:
        alert.is_resolved = not alert.is_resolved
        alert.save(update_fields=['is_resolved'])
        return JsonResponse({
            'success': True,
            'is_resolved': alert.is_resolved,
        })
    except Exception as e:
        return JsonResponse(
            {'success': False, 'error': str(e)},
            status=500,
        )
