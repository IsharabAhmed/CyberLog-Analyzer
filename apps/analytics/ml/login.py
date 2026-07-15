"""
Suspicious login detection.

Analyses parsed log entries for suspicious authentication patterns including
failed logins, off-hours access, and indicators of credential compromise.
"""

import logging
from collections import defaultdict
from datetime import datetime

import pandas as pd

logger = logging.getLogger(__name__)

# Keywords that indicate authentication-related actions
AUTH_KEYWORDS = {'LOGIN', 'AUTH', 'AUTHENTICATE', 'SESSION', 'PASSWORD',
                 'CREDENTIAL', 'LOGON', 'SIGNIN', 'SIGN-IN', 'SSO'}
FAILURE_KEYWORDS = {'FAIL', 'DENIED', 'DROP', 'REJECT', 'INVALID', 'BLOCK',
                     'FAILED', 'REFUSED', 'FORBIDDEN', 'UNAUTHORIZED', 'ERROR'}
SUCCESS_KEYWORDS = {'SUCCESS', 'ACCEPTED', 'GRANTED', 'OK', 'ALLOW', 'PERMITTED'}


def _is_auth_related(entry: dict) -> bool:
    """Return True if the entry appears to be authentication-related."""
    action = (entry.get('action') or '').upper()
    desc = (entry.get('description') or '').upper()
    return any(kw in action or kw in desc for kw in AUTH_KEYWORDS)


def _is_failure(entry: dict) -> bool:
    """Return True if the entry represents a failed action."""
    action = (entry.get('action') or '').upper()
    desc = (entry.get('description') or '').upper()
    return any(kw in action or kw in desc for kw in FAILURE_KEYWORDS)


def _is_success(entry: dict) -> bool:
    """Return True if the entry represents a successful action."""
    action = (entry.get('action') or '').upper()
    desc = (entry.get('description') or '').upper()
    return any(kw in action or kw in desc for kw in SUCCESS_KEYWORDS)


def _parse_ts(entry: dict):
    """Parse the timestamp from an entry, returning a datetime or None."""
    ts = entry.get('timestamp')
    if ts is None:
        return None
    if isinstance(ts, str):
        ts = pd.to_datetime(ts, errors='coerce')
        if ts is pd.NaT:
            return None
    return ts


class SuspiciousLoginDetector:
    """Detect suspicious login patterns in log entries.

    Performs four independent checks:
    1. Failed login attempts (especially from unknown IPs)
    2. Successful logins during off-hours
    3. Multiple failed logins followed by a success (potential compromise)
    4. Successful login from an IP that previously failed

    Attributes:
        off_hours_start: Hour (0-23) when off-hours begin.
        off_hours_end: Hour (0-23) when off-hours end.
    """

    def __init__(self, off_hours_start: int = 22, off_hours_end: int = 6):
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    def _is_off_hours(self, ts) -> bool:
        """Return True if the timestamp falls within off-hours."""
        if ts is None:
            return False
        hour = ts.hour
        if self.off_hours_start > self.off_hours_end:
            # Wraps around midnight, e.g. 22:00 - 06:00
            return hour >= self.off_hours_start or hour < self.off_hours_end
        return self.off_hours_start <= hour < self.off_hours_end

    def analyze(self, entries_data: list[dict]) -> list[dict]:
        """Analyse entries for suspicious login patterns.

        Args:
            entries_data: List of log entry dictionaries.

        Returns:
            List of alert dicts, each containing:
            - entry_index: index into entries_data
            - alert_type: 'suspicious_login'
            - severity: critical/high/medium/low
            - title: short description
            - description: detailed description
            - detection_method: which check triggered the alert
            - confidence: float 0-1
            - source_ip: source IP if available
            - metadata: additional context dict
        """
        if not entries_data:
            return []

        alerts: list[dict] = []

        # Pre-filter to auth-related entries (keep original indices)
        auth_entries: list[tuple[int, dict]] = [
            (idx, entry) for idx, entry in enumerate(entries_data)
            if _is_auth_related(entry)
        ]

        if not auth_entries:
            return []

        # Build per-IP history for checks 3 & 4
        ip_history: dict[str, list[tuple[int, dict, bool]]] = defaultdict(list)
        for idx, entry in auth_entries:
            ip = entry.get('source_ip')
            if ip:
                failed = _is_failure(entry)
                ip_history[ip].append((idx, entry, failed))

        # --- Check 1: Failed login attempts ---
        for idx, entry in auth_entries:
            if _is_failure(entry):
                severity_str = (entry.get('severity') or 'info').lower()
                # Map entry severity to alert severity
                if severity_str in ('critical', 'high'):
                    alert_severity = 'high'
                    confidence = 0.7
                else:
                    alert_severity = 'low'
                    confidence = 0.4

                ip = entry.get('source_ip') or 'unknown'
                alerts.append({
                    'entry_index': idx,
                    'alert_type': 'suspicious_login',
                    'severity': alert_severity,
                    'title': f'Failed login attempt from {ip}',
                    'description': (
                        f"A failed authentication attempt was detected from IP {ip}. "
                        f"Action: {entry.get('action', 'N/A')}. "
                        f"Description: {entry.get('description', 'N/A')}"
                    ),
                    'detection_method': 'failed_login_detection',
                    'confidence': confidence,
                    'source_ip': entry.get('source_ip'),
                    'metadata': {
                        'action': entry.get('action'),
                        'original_severity': severity_str,
                    },
                })

        # --- Check 2: Successful login during off-hours ---
        for idx, entry in auth_entries:
            if _is_success(entry):
                ts = _parse_ts(entry)
                if self._is_off_hours(ts):
                    ip = entry.get('source_ip') or 'unknown'
                    hour_str = ts.strftime('%H:%M') if ts else 'unknown'
                    alerts.append({
                        'entry_index': idx,
                        'alert_type': 'suspicious_login',
                        'severity': 'medium',
                        'title': f'Off-hours login from {ip} at {hour_str}',
                        'description': (
                            f"A successful authentication occurred during off-hours "
                            f"({self.off_hours_start}:00-{self.off_hours_end}:00) "
                            f"from IP {ip} at {hour_str}. This may indicate "
                            f"unauthorized access."
                        ),
                        'detection_method': 'off_hours_login_detection',
                        'confidence': 0.6,
                        'source_ip': entry.get('source_ip'),
                        'metadata': {
                            'login_hour': ts.hour if ts else None,
                            'off_hours_range': f"{self.off_hours_start}-{self.off_hours_end}",
                        },
                    })

        # --- Check 3: Multiple failures followed by success (potential compromise) ---
        for ip, history in ip_history.items():
            # Sort by timestamp
            sorted_history = sorted(
                history,
                key=lambda x: _parse_ts(x[1]) or datetime.min,
            )

            consecutive_failures = 0
            failure_indices = []

            for idx, entry, failed in sorted_history:
                if failed:
                    consecutive_failures += 1
                    failure_indices.append(idx)
                else:
                    # Successful login after failures
                    if consecutive_failures >= 2 and _is_success(entry):
                        if consecutive_failures >= 5:
                            severity = 'critical'
                            confidence = 0.9
                        elif consecutive_failures >= 3:
                            severity = 'high'
                            confidence = 0.8
                        else:
                            severity = 'medium'
                            confidence = 0.65

                        alerts.append({
                            'entry_index': idx,
                            'alert_type': 'suspicious_login',
                            'severity': severity,
                            'title': (
                                f'Potential credential compromise: {consecutive_failures} '
                                f'failures then success from {ip}'
                            ),
                            'description': (
                                f"IP {ip} had {consecutive_failures} consecutive failed "
                                f"login attempts followed by a successful login. This "
                                f"pattern is consistent with credential compromise or "
                                f"brute-force success."
                            ),
                            'detection_method': 'failure_then_success_detection',
                            'confidence': confidence,
                            'source_ip': ip,
                            'metadata': {
                                'failure_count': consecutive_failures,
                                'failure_entry_indices': failure_indices.copy(),
                            },
                        })

                    # Reset counters
                    consecutive_failures = 0
                    failure_indices = []

        # --- Check 4: Successful login from IP with prior failures ---
        ips_with_failures: set[str] = set()
        for ip, history in ip_history.items():
            if any(failed for _, _, failed in history):
                ips_with_failures.add(ip)

        for idx, entry in auth_entries:
            if _is_success(entry):
                ip = entry.get('source_ip')
                if ip and ip in ips_with_failures:
                    # Count total failures for this IP
                    total_failures = sum(
                        1 for _, _, failed in ip_history.get(ip, []) if failed
                    )
                    # Don't duplicate check 3 alerts – only alert when there
                    # is at least 1 failure but the pattern is not necessarily
                    # consecutive (already covered by check 3 when consecutive).
                    if total_failures >= 1:
                        alerts.append({
                            'entry_index': idx,
                            'alert_type': 'suspicious_login',
                            'severity': 'medium' if total_failures >= 3 else 'low',
                            'title': (
                                f'Login from previously-failing IP {ip} '
                                f'({total_failures} prior failures)'
                            ),
                            'description': (
                                f"IP {ip} successfully authenticated after having "
                                f"{total_failures} total failed attempt(s) in this log. "
                                f"Review whether this access is legitimate."
                            ),
                            'detection_method': 'prior_failure_ip_detection',
                            'confidence': min(0.5 + total_failures * 0.05, 0.85),
                            'source_ip': ip,
                            'metadata': {
                                'total_prior_failures': total_failures,
                            },
                        })

        logger.info(
            f"Suspicious login detector generated {len(alerts)} alerts "
            f"from {len(auth_entries)} auth entries."
        )
        return alerts
