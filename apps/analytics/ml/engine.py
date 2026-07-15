import time
import logging
import numpy as np
from django.conf import settings
from .features import FeatureExtractor
from .anomaly import AnomalyDetector
from .login import SuspiciousLoginDetector
from .bruteforce import BruteForceDetector
from .traffic import TrafficAnalyzer
from .scoring import RiskScorer

logger = logging.getLogger(__name__)

class AnalysisEngine:
    """Main ML analysis engine that orchestrates all detection modules."""
    
    def __init__(self):
        ml_config = getattr(settings, 'ML_CONFIG', {})
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector(
            contamination=ml_config.get('ANOMALY_CONTAMINATION', 0.1)
        )
        self.login_detector = SuspiciousLoginDetector(
            off_hours_start=ml_config.get('OFF_HOURS_START', 22),
            off_hours_end=ml_config.get('OFF_HOURS_END', 6)
        )
        self.bruteforce_detector = BruteForceDetector(
            threshold=ml_config.get('BRUTE_FORCE_THRESHOLD', 5),
            window_minutes=ml_config.get('BRUTE_FORCE_WINDOW_MINUTES', 10)
        )
        self.traffic_analyzer = TrafficAnalyzer()
        self.risk_scorer = RiskScorer(
            weights=ml_config.get('RISK_SCORE_WEIGHTS')
        )
    
    def analyze_log_file(self, log_file) -> dict:
        """Run full analysis pipeline on a LogFile instance."""
        from apps.logs.models import LogEntry
        from apps.analytics.models import Alert, ThreatSummary
        
        start_time = time.time()
        
        entries_qs = LogEntry.objects.filter(log_file=log_file).order_by('timestamp', 'line_number')
        entries_data = list(entries_qs.values(
            'id', 'timestamp', 'source_ip', 'destination_ip',
            'action', 'severity', 'description', 'raw_line',
            'line_number', 'metadata'
        ))
        
        if not entries_data:
            logger.warning(f"No entries found for log file {log_file.id}")
            return {'alerts': [], 'threat_summary': None, 'risk_scores': []}
        
        # 3. Extract features
        features_df = self.feature_extractor.extract_entry_features(entries_data)
        
        # 4. Run anomaly detection
        anomaly_scores = np.zeros(len(entries_data))
        if self.anomaly_detector.train(features_df):
            anomaly_scores = self.anomaly_detector.predict(features_df)
            
        # Add basic anomaly alerts
        alerts_data = []
        for i, score in enumerate(anomaly_scores):
            if score > 0.8:
                alerts_data.append({
                    'entry_index': i,
                    'alert_type': 'anomaly',
                    'severity': 'high' if score > 0.9 else 'medium',
                    'title': 'Anomalous Log Entry',
                    'description': f'Anomaly score: {score:.2f}',
                    'detection_method': 'Isolation Forest',
                    'confidence': score,
                    'source_ip': entries_data[i].get('source_ip'),
                    'metadata': {'anomaly_score': float(score)}
                })
                
        # 5. Run login detector
        alerts_data.extend(self.login_detector.analyze(entries_data))
        
        # 6. Run brute-force detector  
        alerts_data.extend(self.bruteforce_detector.analyze(entries_data))
        
        # 7. Run traffic analyzer
        alerts_data.extend(self.traffic_analyzer.analyze(entries_data))
        
        # 8. Run risk scorer
        risk_scores = self.risk_scorer.score_entries(entries_data, anomaly_scores)
        
        # 9. Update LogEntry risk_scores in database
        entries_to_update = []
        for i, entry_data in enumerate(entries_data):
            # We need to instantiate model objects or just use update() on IDs.
            # But we already have the UUID in entry_data['id']
            # Bulk update requires model instances
            entries_to_update.append(LogEntry(id=entry_data['id'], risk_score=risk_scores[i]))
            
        LogEntry.objects.bulk_update(entries_to_update, ['risk_score'], batch_size=1000)
        
        # 10. Create Alert objects in database
        alerts_to_create = []
        for ad in alerts_data:
            idx = ad.get('entry_index')
            entry_id = entries_data[idx]['id'] if idx is not None else None
            
            alerts_to_create.append(Alert(
                log_file=log_file,
                log_entry_id=entry_id,
                alert_type=ad['alert_type'],
                severity=ad['severity'],
                title=ad['title'],
                description=ad['description'],
                detection_method=ad['detection_method'],
                confidence=ad.get('confidence', 0.5),
                source_ip=ad.get('source_ip'),
                metadata=ad.get('metadata', {})
            ))
            
        created_alerts = Alert.objects.bulk_create(alerts_to_create)
        
        # 11. Create ThreatSummary in database
        total_events = len(entries_data)
        total_alerts = len(created_alerts)
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for a in alerts_to_create:
            if a.severity in severity_counts:
                severity_counts[a.severity] += 1
                
        # Top IPs
        ip_counts = {}
        for a in alerts_to_create:
            ip = a.source_ip
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips_data = [{'ip': ip, 'alert_count': count} for ip, count in top_ips]
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        duration = time.time() - start_time
        
        ts, _ = ThreatSummary.objects.update_or_create(
            log_file=log_file,
            defaults={
                'total_events': total_events,
                'total_alerts': total_alerts,
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low'],
                'top_source_ips': top_ips_data,
                'risk_score_avg': avg_risk,
                'analysis_duration': duration
            }
        )
        
        return {
            'alerts': created_alerts,
            'threat_summary': ts,
            'risk_scores': risk_scores
        }
