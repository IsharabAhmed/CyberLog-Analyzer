import os
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.conf import settings
from apps.logs.models import LogFile, LogEntry
from apps.logs.parsers import get_parser, detect_log_type
from apps.analytics.ml.engine import AnalysisEngine

class Command(BaseCommand):
    help = 'Loads sample log data for testing'

    def handle(self, *args, **options):
        # Create demo user
        user, created = User.objects.get_or_create(username='demo')
        if created:
            user.set_password('demo1234')
            user.save()
            self.stdout.write(self.style.SUCCESS('Created demo user'))

        sample_dir = os.path.join(settings.BASE_DIR, 'sample_logs')
        engine = AnalysisEngine()

        for filename in os.listdir(sample_dir):
            if not filename.endswith('.log'):
                continue
                
            filepath = os.path.join(sample_dir, filename)
            self.stdout.write(f'Processing {filename}...')
            
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            if not lines:
                continue

            log_type = detect_log_type(lines[:10])
            parser = get_parser(log_type)
            
            # Create LogFile
            log_file = LogFile.objects.create(
                user=user,
                filename=filename,
                log_type=log_type,
                status='processing'
            )
            
            entries = []
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                parsed = parser.parse_line(line)
                if parsed:
                    entries.append(LogEntry(
                        log_file=log_file,
                        line_number=i+1,
                        timestamp=parsed.get('timestamp'),
                        source_ip=parsed.get('source_ip'),
                        destination_ip=parsed.get('destination_ip'),
                        action=parsed.get('action', 'UNKNOWN'),
                        severity=parsed.get('severity', 'info'),
                        description=parsed.get('description', ''),
                        raw_line=parsed.get('raw_line', line),
                        metadata=parsed.get('metadata', {})
                    ))
            
            LogEntry.objects.bulk_create(entries)
            log_file.total_entries = len(entries)
            log_file.status = 'completed'
            log_file.save()
            
            self.stdout.write(f'  Parsed {len(entries)} entries. Running ML pipeline...')
            engine.analyze_log_file(log_file)
            self.stdout.write(self.style.SUCCESS(f'  Finished {filename}'))

        self.stdout.write(self.style.SUCCESS('All sample data loaded successfully'))
