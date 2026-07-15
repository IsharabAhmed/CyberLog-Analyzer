"""
Unusual traffic pattern detection.

Analyses log entries for a variety of anomalous and potentially malicious
traffic patterns including volume spikes, port scanning, known scanner
signatures, unusual HTTP methods, and common web-attack signatures (directory
traversal, SQL injection, XSS).
"""

import re
import logging
from collections import Counter, defaultdict
from datetime import timedelta

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# --- Signature databases ---

SCANNER_SIGNATURES = [
    'nikto', 'sqlmap', 'nmap', 'masscan', 'zmap', 'dirbuster', 'gobuster',
    'wfuzz', 'burpsuite', 'burp', 'acunetix', 'nessus', 'openvas',
    'w3af', 'skipfish', 'arachni', 'whatweb', 'wpscan', 'joomscan',
    'nuclei', 'subfinder', 'amass', 'hydra', 'medusa', 'zgrab',
]

UNUSUAL_HTTP_METHODS = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS', 'PATCH'}

SQLI_PATTERNS = [
    r"(?i)union\s+(all\s+)?select",
    r"(?i)select\s+.+\s+from",
    r"(?i)drop\s+(table|database)",
    r"(?i)insert\s+into",
    r"(?i)update\s+.+\s+set",
    r"(?i)or\s+1\s*=\s*1",
    r"(?i)or\s+'1'\s*=\s*'1'",
    r"(?i);\s*--",
    r"(?i)'\s*or\s+'",
    r"(?i)exec(\s+|\()xp_",
    r"(?i)benchmark\s*\(",
    r"(?i)sleep\s*\(",
    r"(?i)waitfor\s+delay",
    r"(?i)cast\s*\(",
    r"(?i)convert\s*\(",
    r"(?i)char\s*\(",
    r"(?i)0x[0-9a-f]+",
]
SQLI_COMPILED = [re.compile(p) for p in SQLI_PATTERNS]

XSS_PATTERNS = [
    r"(?i)<\s*script",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onmouseover\s*=",
    r"(?i)onfocus\s*=",
    r"(?i)onclick\s*=",
    r"(?i)eval\s*\(",
    r"(?i)document\.cookie",
    r"(?i)document\.location",
    r"(?i)window\.location",
    r"(?i)alert\s*\(",
    r"(?i)<\s*img[^>]+on\w+\s*=",
    r"(?i)<\s*iframe",
    r"(?i)<\s*svg[^>]+on\w+\s*=",
]
XSS_COMPILED = [re.compile(p) for p in XSS_PATTERNS]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/\\%]",
    r"\.\.%2f",
    r"%2e%2e%2f",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\\windows\\system32",
    r"\\win\.ini",
    r"/proc/self",
]
TRAVERSAL_COMPILED = [re.compile(p, re.IGNORECASE) for p in TRAVERSAL_PATTERNS]


def _get_text_fields(entry: dict) -> str:
    """Concatenate all text-bearing fields of an entry for pattern matching."""
    parts = [
        entry.get('action') or '',
        entry.get('description') or '',
        entry.get('raw_line') or '',
    ]
    meta = entry.get('metadata') or {}
    if isinstance(meta, dict):
        for key in ('url', 'uri', 'path', 'request_uri', 'request',
                     'query_string', 'user_agent', 'referrer', 'referer'):
            val = meta.get(key)
            if val:
                parts.append(str(val))
    return ' '.join(parts)


def _get_user_agent(entry: dict) -> str:
    """Extract user-agent string from metadata."""
    meta = entry.get('metadata') or {}
    if isinstance(meta, dict):
        for key in ('user_agent', 'useragent', 'User-Agent', 'http_user_agent'):
            val = meta.get(key)
            if val:
                return str(val).lower()
    return ''


def _parse_ts(entry: dict):
    """Parse timestamp from entry."""
    ts = entry.get('timestamp')
    if ts is None:
        return None
    if isinstance(ts, str):
        ts = pd.to_datetime(ts, errors='coerce')
        if ts is pd.NaT:
            return None
    return ts


class TrafficAnalyzer:
    """Detect unusual traffic patterns and deviations from baseline.

    Performs seven independent checks:
    1. Request volume spikes (> 3× average in 5-min windows)
    2. Port scanning (single IP hitting many destination ports)
    3. Known scanner user-agents
    4. Unusual HTTP methods in high volume
    5. Directory traversal signatures
    6. SQL injection signatures
    7. XSS signatures
    """

    def analyze(self, entries_data: list[dict]) -> list[dict]:
        """Analyse entries for unusual traffic patterns.

        Args:
            entries_data: List of log entry dictionaries.

        Returns:
            List of alert dicts with keys: entry_index, alert_type,
            severity, title, description, detection_method, confidence,
            source_ip, metadata.
        """
        if not entries_data:
            return []

        alerts: list[dict] = []

        try:
            alerts.extend(self._check_volume_spikes(entries_data))
        except Exception as exc:
            logger.error(f"Volume spike check failed: {exc}")

        try:
            alerts.extend(self._check_port_scanning(entries_data))
        except Exception as exc:
            logger.error(f"Port scanning check failed: {exc}")

        try:
            alerts.extend(self._check_scanner_signatures(entries_data))
        except Exception as exc:
            logger.error(f"Scanner signature check failed: {exc}")

        try:
            alerts.extend(self._check_unusual_methods(entries_data))
        except Exception as exc:
            logger.error(f"Unusual methods check failed: {exc}")

        try:
            alerts.extend(self._check_directory_traversal(entries_data))
        except Exception as exc:
            logger.error(f"Directory traversal check failed: {exc}")

        try:
            alerts.extend(self._check_sql_injection(entries_data))
        except Exception as exc:
            logger.error(f"SQL injection check failed: {exc}")

        try:
            alerts.extend(self._check_xss(entries_data))
        except Exception as exc:
            logger.error(f"XSS check failed: {exc}")

        logger.info(
            f"Traffic analyzer generated {len(alerts)} alerts "
            f"from {len(entries_data)} entries."
        )
        return alerts

    # ------------------------------------------------------------------
    # Check 1: Request volume spikes
    # ------------------------------------------------------------------
    def _check_volume_spikes(self, entries_data: list[dict]) -> list[dict]:
        """Detect time windows where request volume exceeds 3× the average."""
        alerts: list[dict] = []

        # Collect entries with valid timestamps
        timed = []
        for idx, entry in enumerate(entries_data):
            ts = _parse_ts(entry)
            if ts is not None:
                timed.append((idx, entry, ts))

        if len(timed) < 3:
            return []

        timed.sort(key=lambda x: x[2])
        window_delta = timedelta(minutes=5)

        min_ts = timed[0][2]
        max_ts = timed[-1][2]

        # Count entries per window
        window_counts: list[tuple] = []  # (start, end, count, indices)
        current_start = min_ts

        while current_start <= max_ts:
            window_end = current_start + window_delta
            window_entries = [
                (idx, e) for idx, e, ts in timed
                if current_start <= ts < window_end
            ]
            if window_entries:
                window_counts.append((
                    current_start, window_end,
                    len(window_entries),
                    [idx for idx, _ in window_entries],
                ))
            current_start = window_end

        if not window_counts:
            return []

        counts = [wc[2] for wc in window_counts]
        avg_count = np.mean(counts)

        if avg_count == 0:
            return []

        for start, end, count, indices in window_counts:
            if count > avg_count * 3:
                spike_ratio = count / avg_count
                if spike_ratio >= 10:
                    severity = 'critical'
                    confidence = 0.9
                elif spike_ratio >= 5:
                    severity = 'high'
                    confidence = 0.8
                else:
                    severity = 'medium'
                    confidence = 0.7

                alerts.append({
                    'entry_index': indices[-1],
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': (
                        f'Traffic spike: {count} requests in 5 min '
                        f'({spike_ratio:.1f}× average)'
                    ),
                    'description': (
                        f"Request volume spiked to {count} entries between "
                        f"{start} and {end}, which is {spike_ratio:.1f}× the "
                        f"average of {avg_count:.1f} per window. This may "
                        f"indicate a DDoS attack or automated scanning."
                    ),
                    'detection_method': 'volume_spike_detection',
                    'confidence': confidence,
                    'source_ip': None,
                    'metadata': {
                        'window_start': str(start),
                        'window_end': str(end),
                        'count': count,
                        'average': round(avg_count, 2),
                        'spike_ratio': round(spike_ratio, 2),
                    },
                })

        return alerts

    # ------------------------------------------------------------------
    # Check 2: Port scanning
    # ------------------------------------------------------------------
    def _check_port_scanning(self, entries_data: list[dict]) -> list[dict]:
        """Detect single IPs hitting many different destination ports."""
        alerts: list[dict] = []
        PORT_SCAN_THRESHOLD = 10

        ip_ports: dict[str, set] = defaultdict(set)
        ip_last_idx: dict[str, int] = {}

        for idx, entry in enumerate(entries_data):
            ip = entry.get('source_ip')
            if not ip:
                continue
            ip_last_idx[ip] = idx

            meta = entry.get('metadata') or {}
            if isinstance(meta, dict):
                for key in ('dest_port', 'destination_port', 'port', 'dport'):
                    val = meta.get(key)
                    if val is not None:
                        try:
                            ip_ports[ip].add(int(val))
                        except (ValueError, TypeError):
                            pass

        for ip, ports in ip_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                port_count = len(ports)
                if port_count >= 100:
                    severity = 'critical'
                    confidence = 0.95
                elif port_count >= 50:
                    severity = 'high'
                    confidence = 0.85
                else:
                    severity = 'medium'
                    confidence = 0.75

                alerts.append({
                    'entry_index': ip_last_idx.get(ip, 0),
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': f'Port scan detected from {ip}: {port_count} ports',
                    'description': (
                        f"IP {ip} targeted {port_count} unique destination ports. "
                        f"This pattern is consistent with port scanning or "
                        f"service enumeration."
                    ),
                    'detection_method': 'port_scan_detection',
                    'confidence': confidence,
                    'source_ip': ip,
                    'metadata': {
                        'unique_ports': port_count,
                        'sample_ports': sorted(list(ports))[:20],
                    },
                })

        return alerts

    # ------------------------------------------------------------------
    # Check 3: Scanner signatures
    # ------------------------------------------------------------------
    def _check_scanner_signatures(self, entries_data: list[dict]) -> list[dict]:
        """Detect known vulnerability scanner user-agents."""
        alerts: list[dict] = []
        flagged_ips: dict[str, dict] = {}  # ip → {scanner, count, last_idx}

        for idx, entry in enumerate(entries_data):
            ua = _get_user_agent(entry)
            if not ua:
                continue

            for scanner in SCANNER_SIGNATURES:
                if scanner in ua:
                    ip = entry.get('source_ip') or 'unknown'
                    if ip not in flagged_ips:
                        flagged_ips[ip] = {
                            'scanner': scanner,
                            'count': 0,
                            'last_idx': idx,
                        }
                    flagged_ips[ip]['count'] += 1
                    flagged_ips[ip]['last_idx'] = idx
                    break

        for ip, info in flagged_ips.items():
            severity = 'high' if info['count'] >= 10 else 'medium'
            alerts.append({
                'entry_index': info['last_idx'],
                'alert_type': 'unusual_traffic',
                'severity': severity,
                'title': (
                    f'Scanner detected: {info["scanner"]} from {ip} '
                    f'({info["count"]} requests)'
                ),
                'description': (
                    f"Known vulnerability scanner signature '{info['scanner']}' "
                    f"detected in user-agent from IP {ip}. "
                    f"Total matching requests: {info['count']}."
                ),
                'detection_method': 'scanner_signature_detection',
                'confidence': 0.9,
                'source_ip': ip if ip != 'unknown' else None,
                'metadata': {
                    'scanner_name': info['scanner'],
                    'request_count': info['count'],
                },
            })

        return alerts

    # ------------------------------------------------------------------
    # Check 4: Unusual HTTP methods
    # ------------------------------------------------------------------
    def _check_unusual_methods(self, entries_data: list[dict]) -> list[dict]:
        """Flag high volumes of unusual HTTP methods."""
        alerts: list[dict] = []
        UNUSUAL_METHOD_THRESHOLD = 5

        method_counts: dict[str, list[int]] = defaultdict(list)

        for idx, entry in enumerate(entries_data):
            meta = entry.get('metadata') or {}
            if isinstance(meta, dict):
                method = (meta.get('method') or meta.get('http_method') or '').upper()
            else:
                method = ''

            # Also check action field for HTTP methods
            if not method:
                action = (entry.get('action') or '').upper()
                for m in UNUSUAL_HTTP_METHODS:
                    if m in action:
                        method = m
                        break

            if method in UNUSUAL_HTTP_METHODS:
                method_counts[method].append(idx)

        for method, indices in method_counts.items():
            if len(indices) >= UNUSUAL_METHOD_THRESHOLD:
                count = len(indices)
                severity = 'high' if count >= 20 else 'medium'
                alerts.append({
                    'entry_index': indices[-1],
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': f'Unusual HTTP method {method}: {count} requests',
                    'description': (
                        f"Detected {count} requests using the {method} HTTP "
                        f"method. High volumes of {method} requests may indicate "
                        f"probing, resource manipulation, or API abuse."
                    ),
                    'detection_method': 'unusual_method_detection',
                    'confidence': 0.65,
                    'source_ip': None,
                    'metadata': {
                        'method': method,
                        'count': count,
                        'sample_indices': indices[:10],
                    },
                })

        return alerts

    # ------------------------------------------------------------------
    # Check 5: Directory traversal
    # ------------------------------------------------------------------
    def _check_directory_traversal(self, entries_data: list[dict]) -> list[dict]:
        """Detect directory traversal attack signatures."""
        alerts: list[dict] = []

        for idx, entry in enumerate(entries_data):
            text = _get_text_fields(entry)
            if not text:
                continue

            matched_patterns = []
            for pattern in TRAVERSAL_COMPILED:
                if pattern.search(text):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                ip = entry.get('source_ip') or 'unknown'
                severity = 'high' if len(matched_patterns) >= 2 else 'medium'
                alerts.append({
                    'entry_index': idx,
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': f'Directory traversal attempt from {ip}',
                    'description': (
                        f"Directory traversal patterns detected in request from "
                        f"IP {ip}. Matched {len(matched_patterns)} pattern(s). "
                        f"This may be an attempt to access files outside the "
                        f"web root."
                    ),
                    'detection_method': 'directory_traversal_detection',
                    'confidence': 0.85,
                    'source_ip': entry.get('source_ip'),
                    'metadata': {
                        'matched_patterns': matched_patterns,
                        'pattern_count': len(matched_patterns),
                    },
                })

        return alerts

    # ------------------------------------------------------------------
    # Check 6: SQL injection
    # ------------------------------------------------------------------
    def _check_sql_injection(self, entries_data: list[dict]) -> list[dict]:
        """Detect SQL injection attempt signatures."""
        alerts: list[dict] = []

        for idx, entry in enumerate(entries_data):
            text = _get_text_fields(entry)
            if not text:
                continue

            matched_patterns = []
            for pattern in SQLI_COMPILED:
                if pattern.search(text):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                ip = entry.get('source_ip') or 'unknown'
                if len(matched_patterns) >= 3:
                    severity = 'critical'
                    confidence = 0.95
                elif len(matched_patterns) >= 2:
                    severity = 'high'
                    confidence = 0.85
                else:
                    severity = 'medium'
                    confidence = 0.75

                alerts.append({
                    'entry_index': idx,
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': f'SQL injection attempt from {ip}',
                    'description': (
                        f"SQL injection signatures detected in request from "
                        f"IP {ip}. Matched {len(matched_patterns)} pattern(s). "
                        f"This may be an attempt to extract or manipulate "
                        f"database contents."
                    ),
                    'detection_method': 'sql_injection_detection',
                    'confidence': confidence,
                    'source_ip': entry.get('source_ip'),
                    'metadata': {
                        'matched_patterns': matched_patterns,
                        'pattern_count': len(matched_patterns),
                    },
                })

        return alerts

    # ------------------------------------------------------------------
    # Check 7: XSS
    # ------------------------------------------------------------------
    def _check_xss(self, entries_data: list[dict]) -> list[dict]:
        """Detect cross-site scripting (XSS) attempt signatures."""
        alerts: list[dict] = []

        for idx, entry in enumerate(entries_data):
            text = _get_text_fields(entry)
            if not text:
                continue

            matched_patterns = []
            for pattern in XSS_COMPILED:
                if pattern.search(text):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                ip = entry.get('source_ip') or 'unknown'
                if len(matched_patterns) >= 3:
                    severity = 'critical'
                    confidence = 0.9
                elif len(matched_patterns) >= 2:
                    severity = 'high'
                    confidence = 0.8
                else:
                    severity = 'medium'
                    confidence = 0.7

                alerts.append({
                    'entry_index': idx,
                    'alert_type': 'unusual_traffic',
                    'severity': severity,
                    'title': f'XSS attempt detected from {ip}',
                    'description': (
                        f"Cross-site scripting (XSS) patterns detected in "
                        f"request from IP {ip}. Matched "
                        f"{len(matched_patterns)} pattern(s). This may be an "
                        f"attempt to inject malicious scripts."
                    ),
                    'detection_method': 'xss_detection',
                    'confidence': confidence,
                    'source_ip': entry.get('source_ip'),
                    'metadata': {
                        'matched_patterns': matched_patterns,
                        'pattern_count': len(matched_patterns),
                    },
                })

        return alerts
