"""
Views for the main dashboard, report generation, and report downloads.

Provides the central overview dashboard with summary statistics and recent
activity, a report configuration page, and a download endpoint that generates
CSV or PDF reports with alert data and severity distribution charts.
"""

import csv
import io
from datetime import datetime

from django.shortcuts import render
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from apps.logs.models import LogFile, LogEntry
from apps.analytics.models import Alert

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF


@login_required
def dashboard_view(request):
    """
    Main dashboard overview showing summary statistics.

    Context includes:
        - total_events: Count of all log entries for the user
        - total_alerts: Count of all alerts for the user
        - total_files: Count of all uploaded log files
        - critical_alerts: Count of unresolved critical alerts
        - recent_alerts: 10 most recent alerts
        - recent_files: 5 most recently uploaded files
    """
    user = request.user

    try:
        total_events = LogEntry.objects.filter(log_file__user=user).count()
        total_alerts = Alert.objects.filter(log_file__user=user).count()
        total_files = user.log_files.count()
        critical_alerts = Alert.objects.filter(
            log_file__user=user,
            severity='critical',
            is_resolved=False,
        ).count()
        recent_alerts = Alert.objects.filter(
            log_file__user=user
        ).select_related('log_file').order_by('-created_at')[:10]
        recent_files = user.log_files.all().order_by('-uploaded_at')[:5]
    except Exception as e:
        messages.error(request, f'Error loading dashboard data: {str(e)}')
        total_events = 0
        total_alerts = 0
        total_files = 0
        critical_alerts = 0
        recent_alerts = []
        recent_files = []

    context = {
        'total_events': total_events,
        'total_alerts': total_alerts,
        'total_files': total_files,
        'critical_alerts': critical_alerts,
        'recent_alerts': recent_alerts,
        'recent_files': recent_files,
    }

    return render(request, 'dashboard/overview.html', context)


@login_required
def reports_view(request):
    """
    Display the report generation page.

    Context includes:
        - log_files: All of the user's uploaded log files
        - alerts_summary: Counts of alerts by severity
    """
    user = request.user

    try:
        log_files = user.log_files.all().order_by('-uploaded_at')
        user_alerts = Alert.objects.filter(log_file__user=user)
        alerts_summary = {
            'total': user_alerts.count(),
            'critical': user_alerts.filter(severity='critical').count(),
            'high': user_alerts.filter(severity='high').count(),
            'medium': user_alerts.filter(severity='medium').count(),
            'low': user_alerts.filter(severity='low').count(),
        }
    except Exception as e:
        messages.error(request, f'Error loading report data: {str(e)}')
        log_files = []
        alerts_summary = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    context = {
        'log_files': log_files,
        'alerts_summary': alerts_summary,
    }

    return render(request, 'dashboard/reports.html', context)


@login_required
def report_download_view(request):
    """
    Generate and download a report in CSV or PDF format.

    Query parameters:
        - format: 'csv' or 'pdf' (default: 'csv')
        - date_from: Start date for filtering alerts (YYYY-MM-DD)
        - date_to: End date for filtering alerts (YYYY-MM-DD)

    CSV report includes all alert fields within the date range.
    PDF report includes a formatted header, summary statistics,
    alert table, and a severity distribution bar chart.
    """
    user = request.user
    report_format = request.GET.get('format', 'csv').strip().lower()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    try:
        # Base queryset: user's alerts
        alerts = Alert.objects.filter(
            log_file__user=user
        ).select_related('log_file').order_by('-created_at')

        # Apply date filters
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                alerts = alerts.filter(created_at__date__gte=from_date.date())
            except ValueError:
                messages.error(request, 'Invalid date_from format. Use YYYY-MM-DD.')
                return render(request, 'dashboard/reports.html')

        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                alerts = alerts.filter(created_at__date__lte=to_date.date())
            except ValueError:
                messages.error(request, 'Invalid date_to format. Use YYYY-MM-DD.')
                return render(request, 'dashboard/reports.html')

        if report_format == 'pdf':
            return _generate_pdf_report(alerts, date_from, date_to, user)
        else:
            return _generate_csv_report(alerts, date_from, date_to)

    except Exception as e:
        messages.error(request, f'Error generating report: {str(e)}')
        return render(request, 'dashboard/reports.html')


def _generate_csv_report(alerts, date_from, date_to):
    """
    Generate a CSV report of alerts.

    Args:
        alerts: QuerySet of Alert objects.
        date_from: Start date string (for filename).
        date_to: End date string (for filename).

    Returns:
        HttpResponse with CSV content and download headers.
    """
    response = HttpResponse(content_type='text/csv')
    date_range = f'_{date_from}_to_{date_to}' if date_from or date_to else ''
    response['Content-Disposition'] = f'attachment; filename="security_alerts{date_range}.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Alert ID',
        'Created At',
        'Severity',
        'Alert Type',
        'Title',
        'Description',
        'Source IP',
        'Detection Method',
        'Confidence',
        'Resolved',
        'Log File',
    ])

    for alert in alerts:
        writer.writerow([
            str(alert.id),
            alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            alert.severity,
            alert.alert_type,
            alert.title,
            alert.description,
            alert.source_ip or 'N/A',
            alert.detection_method,
            f'{alert.confidence:.2f}',
            'Yes' if alert.is_resolved else 'No',
            alert.log_file.filename if alert.log_file else 'N/A',
        ])

    return response


def _generate_pdf_report(alerts, date_from, date_to, user):
    """
    Generate a PDF report with summary stats, alert table, and severity chart.

    Args:
        alerts: QuerySet of Alert objects.
        date_from: Start date string.
        date_to: End date string.
        user: The requesting user.

    Returns:
        HttpResponse with PDF content and download headers.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=1 * cm,
        leftMargin=1 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Title'],
        fontSize=22,
        spaceAfter=12,
        textColor=colors.HexColor('#1e293b'),
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=20,
        textColor=colors.HexColor('#64748b'),
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#334155'),
    )

    elements = []

    # Title
    elements.append(Paragraph('Cybersecurity Alert Report', title_style))

    # Date range
    date_range_text = 'All time'
    if date_from and date_to:
        date_range_text = f'{date_from} to {date_to}'
    elif date_from:
        date_range_text = f'From {date_from}'
    elif date_to:
        date_range_text = f'Until {date_to}'

    elements.append(Paragraph(
        f'Generated for: {user.username} | Date Range: {date_range_text} | '
        f'Generated on: {timezone.now().strftime("%Y-%m-%d %H:%M")}',
        subtitle_style,
    ))

    # Summary statistics
    total_alerts = alerts.count()
    severity_counts = {
        'critical': alerts.filter(severity='critical').count(),
        'high': alerts.filter(severity='high').count(),
        'medium': alerts.filter(severity='medium').count(),
        'low': alerts.filter(severity='low').count(),
    }
    resolved_count = alerts.filter(is_resolved=True).count()

    elements.append(Paragraph('Summary Statistics', heading_style))

    summary_data = [
        ['Total Alerts', 'Critical', 'High', 'Medium', 'Low', 'Resolved'],
        [
            str(total_alerts),
            str(severity_counts['critical']),
            str(severity_counts['high']),
            str(severity_counts['medium']),
            str(severity_counts['low']),
            str(resolved_count),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[3 * cm] * 6)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f1f5f9')),
        ('FONTSIZE', (0, 1), (-1, 1), 11),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 6),
        ('TOPPADDING', (0, 1), (-1, 1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Severity distribution bar chart
    elements.append(Paragraph('Severity Distribution', heading_style))

    drawing = Drawing(400, 200)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.height = 140
    chart.width = 300
    chart.data = [[
        severity_counts['critical'],
        severity_counts['high'],
        severity_counts['medium'],
        severity_counts['low'],
    ]]
    chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
    chart.categoryAxis.labels.fontSize = 9
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 8
    chart.bars[0].fillColor = colors.HexColor('#ef4444')

    # Color each bar individually
    severity_colors = [
        colors.HexColor('#ef4444'),  # Critical - red
        colors.HexColor('#f97316'),  # High - orange
        colors.HexColor('#eab308'),  # Medium - yellow
        colors.HexColor('#3b82f6'),  # Low - blue
    ]
    for i, color in enumerate(severity_colors):
        chart.bars[0].fillColor = color  # Default; individual bar coloring below

    # Use itemColors for per-bar coloring
    chart.bars.strokeColor = None
    chart.bars[0].fillColor = colors.HexColor('#ef4444')

    drawing.add(chart)
    elements.append(drawing)
    elements.append(Spacer(1, 15))

    # Alert details table
    elements.append(Paragraph('Alert Details', heading_style))

    table_data = [
        ['Severity', 'Type', 'Title', 'Source IP', 'Confidence', 'Date', 'Resolved'],
    ]

    for alert in alerts[:100]:  # Limit to 100 rows for PDF readability
        table_data.append([
            alert.severity.upper(),
            alert.alert_type.replace('_', ' ').title(),
            Paragraph(
                alert.title[:60] + ('...' if len(alert.title) > 60 else ''),
                styles['Normal'],
            ),
            str(alert.source_ip or 'N/A'),
            f'{alert.confidence:.0%}',
            alert.created_at.strftime('%Y-%m-%d %H:%M'),
            'Yes' if alert.is_resolved else 'No',
        ])

    if len(table_data) > 1:
        col_widths = [2 * cm, 3 * cm, 8 * cm, 3.5 * cm, 2 * cm, 3.5 * cm, 2 * cm]
        alert_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        # Severity-based row coloring
        severity_row_colors = {
            'CRITICAL': colors.HexColor('#fef2f2'),
            'HIGH': colors.HexColor('#fff7ed'),
            'MEDIUM': colors.HexColor('#fefce8'),
            'LOW': colors.HexColor('#eff6ff'),
        }

        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (4, 0), (4, -1), 'CENTER'),
            ('ALIGN', (6, 0), (6, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [
                colors.white, colors.HexColor('#f8fafc'),
            ]),
        ]

        # Apply severity-based row colors
        for i, row in enumerate(table_data[1:], start=1):
            sev = row[0] if isinstance(row[0], str) else ''
            if sev in severity_row_colors:
                style_commands.append(
                    ('BACKGROUND', (0, i), (-1, i), severity_row_colors[sev])
                )

        alert_table.setStyle(TableStyle(style_commands))
        elements.append(alert_table)
    else:
        elements.append(Paragraph('No alerts found for the selected date range.', styles['Normal']))

    # Build PDF
    doc.build(elements)
    buffer.seek(0)

    date_range_filename = f'_{date_from}_to_{date_to}' if date_from or date_to else ''
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = (
        f'attachment; filename="security_report{date_range_filename}.pdf"'
    )

    return response
