"""
Views for log file upload, listing, and detail inspection.

Handles the complete log file lifecycle: upload with automatic type detection,
parsing via the appropriate parser, ML analysis, and browsing of parsed entries
with search, filtering, and pagination.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils import timezone
from django.db.models import Q

from apps.logs.models import LogFile, LogEntry
from apps.logs.parsers import get_parser, detect_log_type
from apps.analytics.models import Alert, ThreatSummary
from apps.analytics.ml import AnalysisEngine

from .forms import LogUploadForm


@login_required
def upload_view(request):
    """
    Handle log file upload with parsing and ML analysis.

    GET: Display the upload form with drag-and-drop UI.
    POST: Process the uploaded file through these steps:
        1. Save the LogFile record with status='processing'
        2. Read file content (try UTF-8, fallback to Latin-1)
        3. Detect log type if set to 'auto'
        4. Parse each line using the appropriate parser
        5. Bulk-create LogEntry records for performance
        6. Run ML analysis via AnalysisEngine
        7. Update LogFile status to 'completed' or 'failed'
        8. Redirect to the log detail page on success
    """
    if request.method == 'POST':
        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            log_file = form.save(commit=False)
            log_file.user = request.user
            log_file.filename = request.FILES['file'].name
            log_file.status = 'processing'
            log_file.save()

            try:
                # Read file content with encoding fallback
                uploaded_file = request.FILES['file']
                uploaded_file.seek(0)
                try:
                    content = uploaded_file.read().decode('utf-8')
                except UnicodeDecodeError:
                    uploaded_file.seek(0)
                    content = uploaded_file.read().decode('latin-1')

                lines = content.splitlines()
                if not lines:
                    raise ValueError('The uploaded file is empty.')

                # Detect log type if set to auto
                log_type = log_file.log_type
                if log_type == 'auto':
                    sample_lines = lines[:10]
                    log_type = detect_log_type(sample_lines)
                    log_file.log_type = log_type
                    log_file.save(update_fields=['log_type'])

                # Get the appropriate parser
                parser = get_parser(log_type)

                # Parse each line and collect entries for bulk creation
                entries = []
                for line_number, line in enumerate(lines, start=1):
                    line = line.strip()
                    if not line:
                        continue

                    parsed = parser.parse_line(line)
                    if parsed is not None:
                        entry = LogEntry(
                            log_file=log_file,
                            timestamp=parsed.get('timestamp', timezone.now()),
                            source_ip=parsed.get('source_ip', '0.0.0.0'),
                            destination_ip=parsed.get('destination_ip', '0.0.0.0'),
                            action=parsed.get('action', 'unknown'),
                            severity=parsed.get('severity', 'info'),
                            description=parsed.get('description', ''),
                            raw_line=line,
                            line_number=line_number,
                            risk_score=parsed.get('risk_score', 0.0),
                            metadata=parsed.get('metadata', {}),
                        )
                        entries.append(entry)

                # Bulk create entries in batches of 1000 for memory efficiency
                batch_size = 1000
                for i in range(0, len(entries), batch_size):
                    LogEntry.objects.bulk_create(entries[i:i + batch_size])

                # Update log file with total entries and completion status
                log_file.total_entries = len(entries)
                log_file.status = 'completed'
                log_file.processed_at = timezone.now()
                log_file.save(update_fields=['total_entries', 'status', 'processed_at'])

                # Run ML analysis pipeline
                try:
                    engine = AnalysisEngine()
                    engine.analyze_log_file(log_file)
                except Exception as ml_error:
                    # ML analysis failure shouldn't block the upload
                    messages.warning(
                        request,
                        f'Log file parsed successfully, but ML analysis encountered an issue: {str(ml_error)}',
                    )

                messages.success(
                    request,
                    f'Successfully parsed {len(entries)} log entries from "{log_file.filename}".',
                )
                return redirect('logs:detail', pk=log_file.pk)

            except Exception as e:
                log_file.status = 'failed'
                log_file.error_message = str(e)
                log_file.save(update_fields=['status', 'error_message'])
                messages.error(
                    request,
                    f'Failed to process log file: {str(e)}',
                )
                return redirect('logs:upload')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{error}')
    else:
        form = LogUploadForm()

    return render(request, 'logs/upload.html', {'form': form})


@login_required
def log_list_view(request):
    """
    List all log entries for the current user's uploaded files.

    Supports:
        - Search: ?q= searches description, source_ip, and raw_line
        - Severity filter: ?severity= filters by severity level
        - Log type filter: ?log_type= filters by log file type
        - Date range: ?date_from= and ?date_to= filter by timestamp
        - Pagination: 50 entries per page, ?page= to navigate
    """
    user = request.user

    try:
        entries = LogEntry.objects.filter(
            log_file__user=user
        ).select_related('log_file').order_by('-timestamp')

        # Search filter
        search_query = request.GET.get('q', '').strip()
        if search_query:
            entries = entries.filter(
                Q(description__icontains=search_query)
                | Q(source_ip__icontains=search_query)
                | Q(raw_line__icontains=search_query)
            )

        # Severity filter
        severity = request.GET.get('severity', '').strip()
        if severity:
            entries = entries.filter(severity=severity)

        # Log type filter
        log_type = request.GET.get('log_type', '').strip()
        if log_type:
            entries = entries.filter(log_file__log_type=log_type)

        # Date range filters
        date_from = request.GET.get('date_from', '').strip()
        if date_from:
            entries = entries.filter(timestamp__date__gte=date_from)

        date_to = request.GET.get('date_to', '').strip()
        if date_to:
            entries = entries.filter(timestamp__date__lte=date_to)

        total_count = entries.count()

        # Paginate results
        paginator = Paginator(entries, 50)
        page = request.GET.get('page', 1)
        try:
            entries_page = paginator.page(page)
        except PageNotAnInteger:
            entries_page = paginator.page(1)
        except EmptyPage:
            entries_page = paginator.page(paginator.num_pages)

    except Exception as e:
        messages.error(request, f'Error loading log entries: {str(e)}')
        entries_page = []
        total_count = 0
        search_query = ''
        severity = ''
        log_type = ''
        date_from = ''
        date_to = ''

    context = {
        'entries': entries_page,
        'search_query': search_query,
        'severity': severity,
        'log_type': log_type,
        'date_from': date_from,
        'date_to': date_to,
        'total_count': total_count,
    }

    return render(request, 'logs/list.html', context)


@login_required
def log_detail_view(request, pk):
    """
    Display detailed information about a specific uploaded log file.

    Shows the log file metadata, paginated log entries, associated alerts,
    and the threat summary analysis. Only the user who uploaded the file
    can access this view.

    Args:
        pk: UUID primary key of the LogFile.
    """
    log_file = get_object_or_404(LogFile, pk=pk)

    # Ensure the user owns this log file
    if log_file.user != request.user:
        messages.error(request, 'You do not have permission to view this log file.')
        return redirect('logs:list')

    try:
        # Get entries with pagination
        entries_qs = log_file.entries.all().order_by('line_number')
        paginator = Paginator(entries_qs, 50)
        page = request.GET.get('page', 1)
        try:
            entries = paginator.page(page)
        except PageNotAnInteger:
            entries = paginator.page(1)
        except EmptyPage:
            entries = paginator.page(paginator.num_pages)

        # Get alerts for this log file
        alerts = Alert.objects.filter(log_file=log_file).order_by('-created_at')

        # Get threat summary if available
        try:
            threat_summary = log_file.threat_summary
        except ThreatSummary.DoesNotExist:
            threat_summary = None

    except Exception as e:
        messages.error(request, f'Error loading log file details: {str(e)}')
        entries = []
        alerts = []
        threat_summary = None

    context = {
        'log_file': log_file,
        'entries': entries,
        'alerts': alerts,
        'threat_summary': threat_summary,
    }

    return render(request, 'logs/detail.html', context)
