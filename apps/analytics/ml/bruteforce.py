"""
Brute-force attack detection using sliding window analysis.

Identifies IPs that generate a high volume of failed authentication
attempts within a configurable time window, indicative of brute-force
or credential-stuffing attacks.
"""

import logging
from collections import defaultdict
from datetime import timedelta

import pandas as pd

logger = logging.getLogger(__name__)

AUTH_KEYWORDS = {'LOGIN', 'AUTH', 'AUTHENTICATE', 'SESSION', 'PASSWORD',
                 'CREDENTIAL', 'LOGON', 'SIGNIN', 'SIGN-IN', 'SSO'}
FAILURE_KEYWORDS = {'FAIL', 'DENIED', 'DROP', 'REJECT', 'INVALID', 'BLOCK',
                     'FAILED', 'REFUSED', 'FORBIDDEN', 'UNAUTHORIZED', 'ERROR'}


def _is_auth_failure(entry: dict) -> bool:
    """Return True if the entry is a failed authentication attempt."""
    action = (entry.get('action') or '').upper()
    desc = (entry.get('description') or '').upper()
    combined = action + ' ' + desc
    is_auth = any(kw in combined for kw in AUTH_KEYWORDS)
    is_fail = any(kw in combined for kw in FAILURE_KEYWORDS)
    return is_auth and is_fail


def _parse_ts(entry: dict):
    """Parse timestamp, returning a datetime or None."""
    ts = entry.get('timestamp')
    if ts is None:
        return None
    if isinstance(ts, str):
        ts = pd.to_datetime(ts, errors='coerce')
        if ts is pd.NaT:
            return None
    return ts


class BruteForceDetector:
    """Detect brute-force login attempts via sliding-window analysis.

    Groups authentication-failure entries by source IP, then slides a time
    window across each IP's events. When the number of failures in any
    window meets or exceeds the threshold, an alert is raised.

    Severity escalation:
    - >= threshold          → medium
    - >= 2 × threshold      → high
    - >= 3 × threshold      → critical

    Attributes:
        threshold: Minimum failed attempts in a window to trigger an alert.
        window_minutes: Width of the sliding window in minutes.
    """

    def __init__(self, threshold: int = 5, window_minutes: int = 10):
        self.threshold = threshold
        self.window_minutes = window_minutes

    def analyze(self, entries_data: list[dict]) -> list[dict]:
        """Analyse entries for brute-force login patterns.

        Args:
            entries_data: List of log entry dictionaries.

        Returns:
            List of alert dicts, each containing:
            - entry_index: index of the *last* failure in the window
            - alert_type: 'brute_force'
            - severity: 'critical', 'high', or 'medium'
            - title: short description
            - description: detailed description
            - detection_method: 'sliding_window_brute_force'
            - confidence: float 0-1
            - source_ip: the offending IP
            - metadata: additional context (involved indices, window info)
        """
        if not entries_data:
            return []

        # Group auth-failure entries by source IP
        ip_failures: dict[str, list[tuple[int, dict]]] = defaultdict(list)
        for idx, entry in enumerate(entries_data):
            if _is_auth_failure(entry):
                ip = entry.get('source_ip')
                if ip:
                    ip_failures[ip].append((idx, entry))

        if not ip_failures:
            return []

        alerts: list[dict] = []
        window_delta = timedelta(minutes=self.window_minutes)

        for ip, failures in ip_failures.items():
            # Sort by timestamp
            timed_failures = []
            for idx, entry in failures:
                ts = _parse_ts(entry)
                if ts is not None:
                    timed_failures.append((idx, entry, ts))

            if len(timed_failures) < self.threshold:
                continue

            timed_failures.sort(key=lambda x: x[2])

            # Sliding window using two-pointer technique
            already_alerted_windows: set[tuple] = set()
            left = 0

            for right in range(len(timed_failures)):
                # Advance left pointer to maintain window size
                while (timed_failures[right][2] - timed_failures[left][2]) > window_delta:
                    left += 1

                window_count = right - left + 1

                if window_count >= self.threshold:
                    # Create a hashable key for this window to avoid duplicates
                    window_key = (
                        timed_failures[left][0],   # first entry index
                        timed_failures[right][0],  # last entry index
                    )
                    if window_key in already_alerted_windows:
                        continue
                    already_alerted_windows.add(window_key)

                    # Determine severity based on escalation
                    if window_count >= self.threshold * 3:
                        severity = 'critical'
                        confidence = 0.95
                    elif window_count >= self.threshold * 2:
                        severity = 'high'
                        confidence = 0.85
                    else:
                        severity = 'medium'
                        confidence = 0.75

                    window_start = timed_failures[left][2]
                    window_end = timed_failures[right][2]
                    involved_indices = [
                        timed_failures[i][0] for i in range(left, right + 1)
                    ]

                    alerts.append({
                        'entry_index': timed_failures[right][0],
                        'alert_type': 'brute_force',
                        'severity': severity,
                        'title': (
                            f'Brute-force attack detected from {ip}: '
                            f'{window_count} failures in {self.window_minutes} min'
                        ),
                        'description': (
                            f"IP {ip} generated {window_count} failed authentication "
                            f"attempts between {window_start} and {window_end} "
                            f"(window: {self.window_minutes} minutes). "
                            f"Threshold: {self.threshold}. "
                            f"This is consistent with a brute-force or "
                            f"credential-stuffing attack."
                        ),
                        'detection_method': 'sliding_window_brute_force',
                        'confidence': confidence,
                        'source_ip': ip,
                        'metadata': {
                            'failure_count': window_count,
                            'window_minutes': self.window_minutes,
                            'threshold': self.threshold,
                            'window_start': str(window_start),
                            'window_end': str(window_end),
                            'involved_entry_indices': involved_indices,
                        },
                    })

        # De-duplicate: keep only the highest-severity alert per IP
        best_per_ip: dict[str, dict] = {}
        severity_rank = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}

        for alert in alerts:
            ip = alert['source_ip']
            if ip not in best_per_ip:
                best_per_ip[ip] = alert
            else:
                existing_rank = severity_rank.get(best_per_ip[ip]['severity'], 0)
                new_rank = severity_rank.get(alert['severity'], 0)
                if new_rank > existing_rank:
                    best_per_ip[ip] = alert

        deduplicated = list(best_per_ip.values())

        logger.info(
            f"Brute-force detector generated {len(deduplicated)} alerts "
            f"from {sum(len(v) for v in ip_failures.values())} auth failures "
            f"across {len(ip_failures)} IPs."
        )
        return deduplicated
