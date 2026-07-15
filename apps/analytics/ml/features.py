"""
Feature extraction from log entries for ML models.

Converts raw log entry dictionaries into numerical feature DataFrames
suitable for anomaly detection, clustering, and risk scoring.
"""

import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Action keywords for classification
FAILURE_KEYWORDS = {'FAIL', 'DENIED', 'DROP', 'REJECT', 'INVALID', 'BLOCK',
                    'FAILED', 'REFUSED', 'FORBIDDEN', 'UNAUTHORIZED', 'ERROR'}
AUTH_KEYWORDS = {'LOGIN', 'AUTH', 'AUTHENTICATE', 'SESSION', 'PASSWORD',
                 'CREDENTIAL', 'LOGON', 'SIGNIN', 'SIGN-IN', 'SSO'}

SEVERITY_MAP = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
}


class FeatureExtractor:
    """Extract numerical features from log entries for ML analysis.

    Provides three levels of feature extraction:
    - Entry-level: per-log-entry features (hour, severity, action flags, etc.)
    - IP-level: aggregated features per source IP (request counts, failure rates, etc.)
    - Temporal: time-window-based features for traffic pattern analysis.
    """

    def extract_entry_features(self, entries_data: list[dict]) -> pd.DataFrame:
        """Convert log entry dicts to a feature DataFrame.

        Each entry dict is expected to have keys: timestamp, source_ip, action,
        severity, description, metadata, line_number.

        Features computed per entry:
        - hour_of_day: 0-23
        - is_off_hours: 1 if between 22:00-06:00, else 0
        - day_of_week: 0 (Monday) - 6 (Sunday)
        - is_weekend: 1 if Saturday or Sunday
        - severity_numeric: critical=5, high=4, medium=3, low=2, info=1
        - action_is_failure: 1 if action contains failure keywords
        - action_is_auth: 1 if action contains auth keywords
        - has_source_ip: 1 if source_ip is not None/empty
        - request_size: from metadata if available, else 0
        - status_code: from metadata if available, else 0

        Args:
            entries_data: List of log entry dictionaries.

        Returns:
            pd.DataFrame with one row per entry and numerical features as columns.
        """
        if not entries_data:
            return pd.DataFrame()

        records = []
        for entry in entries_data:
            try:
                ts = entry.get('timestamp')
                if ts is None:
                    hour = 0
                    dow = 0
                elif isinstance(ts, str):
                    ts = pd.to_datetime(ts, errors='coerce')
                    hour = ts.hour if ts is not pd.NaT else 0
                    dow = ts.weekday() if ts is not pd.NaT else 0
                else:
                    hour = ts.hour
                    dow = ts.weekday()

                action_upper = (entry.get('action') or '').upper()
                description_upper = (entry.get('description') or '').upper()

                is_off = 1 if (hour >= 22 or hour < 6) else 0
                is_weekend = 1 if dow >= 5 else 0

                severity_str = (entry.get('severity') or 'info').lower()
                severity_num = SEVERITY_MAP.get(severity_str, 1)

                action_is_failure = 1 if any(kw in action_upper for kw in FAILURE_KEYWORDS) else 0
                # Also check description for failure indicators
                if action_is_failure == 0 and any(kw in description_upper for kw in FAILURE_KEYWORDS):
                    action_is_failure = 1

                action_is_auth = 1 if any(kw in action_upper for kw in AUTH_KEYWORDS) else 0
                if action_is_auth == 0 and any(kw in description_upper for kw in AUTH_KEYWORDS):
                    action_is_auth = 1

                source_ip = entry.get('source_ip')
                has_source_ip = 1 if source_ip else 0

                metadata = entry.get('metadata') or {}
                if isinstance(metadata, str):
                    try:
                        import json
                        metadata = json.loads(metadata)
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}

                request_size = 0
                for key in ('request_size', 'bytes_sent', 'content_length', 'size'):
                    if key in metadata:
                        try:
                            request_size = float(metadata[key])
                        except (ValueError, TypeError):
                            pass
                        break

                status_code = 0
                for key in ('status_code', 'status', 'http_status', 'response_code'):
                    if key in metadata:
                        try:
                            status_code = int(metadata[key])
                        except (ValueError, TypeError):
                            pass
                        break

                records.append({
                    'hour_of_day': hour,
                    'is_off_hours': is_off,
                    'day_of_week': dow,
                    'is_weekend': is_weekend,
                    'severity_numeric': severity_num,
                    'action_is_failure': action_is_failure,
                    'action_is_auth': action_is_auth,
                    'has_source_ip': has_source_ip,
                    'request_size': request_size,
                    'status_code': status_code,
                })
            except Exception as exc:
                logger.debug(f"Error extracting features for entry: {exc}")
                records.append({
                    'hour_of_day': 0,
                    'is_off_hours': 0,
                    'day_of_week': 0,
                    'is_weekend': 0,
                    'severity_numeric': 1,
                    'action_is_failure': 0,
                    'action_is_auth': 0,
                    'has_source_ip': 0,
                    'request_size': 0,
                    'status_code': 0,
                })

        return pd.DataFrame(records)

    def extract_ip_features(self, entries_data: list[dict]) -> pd.DataFrame:
        """Extract per-IP aggregate features.

        Groups entries by source_ip and computes aggregate statistics useful for
        identifying malicious hosts.

        Features per IP:
        - total_requests: count of entries from this IP
        - unique_actions: number of distinct actions
        - failure_rate: fraction of entries with failure actions
        - avg_severity: average severity_numeric
        - max_severity: maximum severity_numeric
        - time_span_minutes: minutes between first and last entry
        - requests_per_minute: total_requests / time_span_minutes
        - unique_destinations: number of unique destination IPs
        - off_hours_ratio: fraction of requests during off-hours
        - port_scan_score: number of unique destination ports targeted

        Args:
            entries_data: List of log entry dictionaries.

        Returns:
            pd.DataFrame indexed by source_ip with aggregate feature columns.
        """
        if not entries_data:
            return pd.DataFrame()

        ip_groups = defaultdict(list)
        for entry in entries_data:
            source_ip = entry.get('source_ip')
            if source_ip:
                ip_groups[source_ip].append(entry)

        if not ip_groups:
            return pd.DataFrame()

        records = []
        for ip, entries in ip_groups.items():
            try:
                total_requests = len(entries)

                actions = [e.get('action', '') or '' for e in entries]
                unique_actions = len(set(actions))

                failure_count = sum(
                    1 for a in actions
                    if any(kw in a.upper() for kw in FAILURE_KEYWORDS)
                )
                failure_rate = failure_count / total_requests if total_requests > 0 else 0.0

                severities = [
                    SEVERITY_MAP.get((e.get('severity') or 'info').lower(), 1)
                    for e in entries
                ]
                avg_severity = np.mean(severities) if severities else 1.0
                max_severity = max(severities) if severities else 1

                timestamps = []
                for e in entries:
                    ts = e.get('timestamp')
                    if ts is not None:
                        if isinstance(ts, str):
                            ts = pd.to_datetime(ts, errors='coerce')
                        if ts is not pd.NaT and ts is not None:
                            timestamps.append(ts)

                if len(timestamps) >= 2:
                    sorted_ts = sorted(timestamps)
                    span = (sorted_ts[-1] - sorted_ts[0]).total_seconds() / 60.0
                    time_span_minutes = max(span, 0.001)  # avoid div-by-zero
                else:
                    time_span_minutes = 0.001

                requests_per_minute = total_requests / time_span_minutes

                destinations = set()
                for e in entries:
                    dest = e.get('destination_ip')
                    if dest:
                        destinations.add(dest)
                unique_destinations = len(destinations)

                off_hours_count = 0
                for e in entries:
                    ts = e.get('timestamp')
                    if ts is not None:
                        if isinstance(ts, str):
                            ts = pd.to_datetime(ts, errors='coerce')
                        if ts is not pd.NaT and ts is not None:
                            if ts.hour >= 22 or ts.hour < 6:
                                off_hours_count += 1
                off_hours_ratio = off_hours_count / total_requests if total_requests > 0 else 0.0

                ports = set()
                for e in entries:
                    meta = e.get('metadata') or {}
                    if isinstance(meta, str):
                        try:
                            import json
                            meta = json.loads(meta)
                        except (json.JSONDecodeError, TypeError):
                            meta = {}
                    for key in ('dest_port', 'destination_port', 'port', 'dport'):
                        if key in meta:
                            try:
                                ports.add(int(meta[key]))
                            except (ValueError, TypeError):
                                pass
                port_scan_score = len(ports)

                records.append({
                    'source_ip': ip,
                    'total_requests': total_requests,
                    'unique_actions': unique_actions,
                    'failure_rate': failure_rate,
                    'avg_severity': avg_severity,
                    'max_severity': max_severity,
                    'time_span_minutes': time_span_minutes,
                    'requests_per_minute': requests_per_minute,
                    'unique_destinations': unique_destinations,
                    'off_hours_ratio': off_hours_ratio,
                    'port_scan_score': port_scan_score,
                })
            except Exception as exc:
                logger.debug(f"Error extracting IP features for {ip}: {exc}")

        df = pd.DataFrame(records)
        if not df.empty:
            df = df.set_index('source_ip')
        return df

    def extract_temporal_features(self, entries_data: list[dict],
                                  window_minutes: int = 5) -> pd.DataFrame:
        """Extract time-window based features for traffic pattern analysis.

        Groups entries into fixed-width time windows and computes aggregate
        statistics for each window. Useful for detecting traffic spikes, shifts
        in behaviour, and DDoS-style patterns.

        Features per window:
        - window_start: start timestamp of the window
        - entries_count: number of entries in the window
        - unique_ips: number of distinct source IPs
        - failure_rate: fraction of failure actions
        - avg_severity: average severity_numeric
        - entropy: Shannon entropy of the action distribution

        Args:
            entries_data: List of log entry dictionaries.
            window_minutes: Width of each time window in minutes.

        Returns:
            pd.DataFrame with one row per time window.
        """
        if not entries_data:
            return pd.DataFrame()

        # Parse timestamps
        timed_entries = []
        for entry in entries_data:
            ts = entry.get('timestamp')
            if ts is None:
                continue
            if isinstance(ts, str):
                ts = pd.to_datetime(ts, errors='coerce')
                if ts is pd.NaT:
                    continue
            timed_entries.append({**entry, '_parsed_ts': ts})

        if not timed_entries:
            return pd.DataFrame()

        timed_entries.sort(key=lambda e: e['_parsed_ts'])

        min_ts = timed_entries[0]['_parsed_ts']
        max_ts = timed_entries[-1]['_parsed_ts']

        # Build windows
        window_delta = timedelta(minutes=window_minutes)
        windows = []
        current_start = min_ts

        while current_start <= max_ts:
            window_end = current_start + window_delta
            window_entries = [
                e for e in timed_entries
                if current_start <= e['_parsed_ts'] < window_end
            ]

            if window_entries:
                entries_count = len(window_entries)

                unique_ips = len(set(
                    e.get('source_ip') for e in window_entries if e.get('source_ip')
                ))

                failure_count = sum(
                    1 for e in window_entries
                    if any(kw in (e.get('action') or '').upper() for kw in FAILURE_KEYWORDS)
                )
                failure_rate = failure_count / entries_count

                severities = [
                    SEVERITY_MAP.get((e.get('severity') or 'info').lower(), 1)
                    for e in window_entries
                ]
                avg_severity = np.mean(severities)

                # Shannon entropy of action distribution
                action_counts = Counter(
                    (e.get('action') or 'UNKNOWN') for e in window_entries
                )
                total = sum(action_counts.values())
                entropy = 0.0
                for count in action_counts.values():
                    if count > 0:
                        p = count / total
                        entropy -= p * np.log2(p)

                windows.append({
                    'window_start': current_start,
                    'entries_count': entries_count,
                    'unique_ips': unique_ips,
                    'failure_rate': failure_rate,
                    'avg_severity': avg_severity,
                    'entropy': entropy,
                })

            current_start = window_end

        return pd.DataFrame(windows)
