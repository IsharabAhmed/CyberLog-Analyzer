"""
Risk scoring system for log entries.

Assigns a composite risk score (0-100) to each log entry by combining
multiple weighted factors: anomaly score, authentication failure indicators,
known attack pattern matches, time-based risk, and geographic/IP risk.
"""

import ipaddress
import re
import logging

import numpy as np

logger = logging.getLogger(__name__)

# --- Pattern databases (shared with traffic.py but kept local for independence) ---

SQLI_QUICK = [
    r"(?i)union\s+select", r"(?i)or\s+1\s*=\s*1", r"(?i)drop\s+table",
    r"(?i);\s*--", r"(?i)'\s*or\s+'", r"(?i)select\s+.+from",
    r"(?i)insert\s+into", r"(?i)exec\s+xp_",
]
SQLI_QUICK_RE = [re.compile(p) for p in SQLI_QUICK]

XSS_QUICK = [
    r"(?i)<\s*script", r"(?i)javascript\s*:", r"(?i)onerror\s*=",
    r"(?i)onload\s*=", r"(?i)eval\s*\(", r"(?i)document\.cookie",
]
XSS_QUICK_RE = [re.compile(p) for p in XSS_QUICK]

TRAVERSAL_QUICK = [
    r"\.\./", r"\.\.\\", r"(?i)/etc/passwd", r"(?i)/etc/shadow",
    r"(?i)\\windows\\system32",
]
TRAVERSAL_QUICK_RE = [re.compile(p) for p in TRAVERSAL_QUICK]

SCANNER_NAMES = [
    'nikto', 'sqlmap', 'nmap', 'masscan', 'dirbuster', 'gobuster',
    'burp', 'acunetix', 'nessus', 'openvas', 'wfuzz', 'nuclei',
    'hydra', 'medusa',
]

FAILURE_KEYWORDS = {'FAIL', 'DENIED', 'DROP', 'REJECT', 'INVALID', 'BLOCK',
                     'FAILED', 'REFUSED', 'FORBIDDEN', 'UNAUTHORIZED', 'ERROR'}
AUTH_KEYWORDS = {'LOGIN', 'AUTH', 'AUTHENTICATE', 'SESSION', 'PASSWORD',
                 'CREDENTIAL', 'LOGON', 'SIGNIN', 'SIGN-IN', 'SSO'}

# RFC 1918 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def _get_text_fields(entry: dict) -> str:
    """Concatenate text-bearing fields for pattern matching."""
    parts = [
        entry.get('action') or '',
        entry.get('description') or '',
        entry.get('raw_line') or '',
    ]
    meta = entry.get('metadata') or {}
    if isinstance(meta, dict):
        for key in ('url', 'uri', 'path', 'request_uri', 'request',
                     'query_string', 'user_agent', 'referrer'):
            val = meta.get(key)
            if val:
                parts.append(str(val))
    return ' '.join(parts)


class RiskScorer:
    """Assign risk scores (0-100) to log entries based on multiple factors.

    Factors and default weights:
    - anomaly (0.30): Isolation Forest / z-score anomaly score
    - auth_failure (0.25): Failed authentication indicators
    - known_pattern (0.20): Signature matches (SQLi, XSS, traversal, scanner)
    - time_risk (0.10): Off-hours access risk
    - geo_risk (0.15): IP reputation heuristic (non-private IPs score higher)

    Each factor is computed as a value in [0, 1]. The final score is the
    weighted sum scaled to [0, 100].

    Attributes:
        weights: Dict mapping factor names to their weights.
    """

    def __init__(self, weights: dict | None = None):
        self.weights = weights or {
            'anomaly': 0.3,
            'auth_failure': 0.25,
            'known_pattern': 0.2,
            'time_risk': 0.1,
            'geo_risk': 0.15,
        }

    def score_entries(self, entries_data: list[dict],
                      anomaly_scores: np.ndarray | None = None) -> list[float]:
        """Compute a composite risk score (0-100) for each entry.

        Args:
            entries_data: List of log entry dictionaries.
            anomaly_scores: Optional 1-D array of anomaly scores (0-1) from
                the anomaly detector, aligned with *entries_data*. If ``None``
                or wrong length, the anomaly factor defaults to 0.

        Returns:
            List of float risk scores in [0, 100], one per entry.
        """
        if not entries_data:
            return []

        n = len(entries_data)

        # Validate / default anomaly scores
        if anomaly_scores is None or len(anomaly_scores) != n:
            anomaly_arr = np.zeros(n)
        else:
            anomaly_arr = np.clip(np.nan_to_num(anomaly_scores, nan=0.0), 0, 1)

        scores: list[float] = []

        for i, entry in enumerate(entries_data):
            try:
                anomaly_val = float(anomaly_arr[i])
                auth_val = self._auth_failure_score(entry)
                pattern_val = self._known_pattern_score(entry)
                time_val = self._time_risk_score(entry)
                geo_val = self._geo_risk_score(entry)

                composite = (
                    anomaly_val * self.weights.get('anomaly', 0.3)
                    + auth_val * self.weights.get('auth_failure', 0.25)
                    + pattern_val * self.weights.get('known_pattern', 0.2)
                    + time_val * self.weights.get('time_risk', 0.1)
                    + geo_val * self.weights.get('geo_risk', 0.15)
                )

                # Scale to 0-100 and clamp
                score = max(0.0, min(100.0, composite * 100.0))
                scores.append(round(score, 2))
            except Exception as exc:
                logger.debug(f"Error scoring entry {i}: {exc}")
                scores.append(0.0)

        return scores

    def _auth_failure_score(self, entry: dict) -> float:
        """Score based on failed authentication indicators (0-1).

        Returns a higher score when the entry is both authentication-related
        and represents a failure. A non-auth failure still receives a modest
        score.
        """
        action = (entry.get('action') or '').upper()
        desc = (entry.get('description') or '').upper()
        combined = action + ' ' + desc

        is_auth = any(kw in combined for kw in AUTH_KEYWORDS)
        is_failure = any(kw in combined for kw in FAILURE_KEYWORDS)

        if is_auth and is_failure:
            return 1.0
        if is_failure:
            return 0.5
        if is_auth:
            # Successful auth is not inherently risky
            return 0.1
        return 0.0

    def _known_pattern_score(self, entry: dict) -> float:
        """Score based on known attack pattern matches (0-1).

        Checks for SQL injection, XSS, directory traversal, and scanner
        signatures. Multiple matches increase the score.
        """
        text = _get_text_fields(entry)
        if not text:
            return 0.0

        score = 0.0

        # SQL injection
        sqli_hits = sum(1 for p in SQLI_QUICK_RE if p.search(text))
        if sqli_hits >= 3:
            score += 0.4
        elif sqli_hits >= 1:
            score += 0.25

        # XSS
        xss_hits = sum(1 for p in XSS_QUICK_RE if p.search(text))
        if xss_hits >= 2:
            score += 0.3
        elif xss_hits >= 1:
            score += 0.15

        # Directory traversal
        traversal_hits = sum(1 for p in TRAVERSAL_QUICK_RE if p.search(text))
        if traversal_hits >= 1:
            score += 0.2

        # Scanner signatures in user-agent
        meta = entry.get('metadata') or {}
        if isinstance(meta, dict):
            ua = ''
            for key in ('user_agent', 'useragent', 'User-Agent', 'http_user_agent'):
                val = meta.get(key)
                if val:
                    ua = str(val).lower()
                    break
            if ua and any(s in ua for s in SCANNER_NAMES):
                score += 0.3

        return min(score, 1.0)

    def _time_risk_score(self, entry: dict) -> float:
        """Score based on off-hours access (0-1).

        Entries during typical off-hours (22:00-06:00) receive a higher score.
        Weekend entries receive a slight additional bump.
        """
        ts = entry.get('timestamp')
        if ts is None:
            return 0.0

        try:
            if isinstance(ts, str):
                import pandas as pd
                ts = pd.to_datetime(ts, errors='coerce')
                if ts is pd.NaT:
                    return 0.0

            hour = ts.hour
            weekday = ts.weekday()

            score = 0.0

            # Core off-hours: midnight to 5 AM
            if 0 <= hour < 5:
                score = 0.8
            # Evening off-hours: 10 PM to midnight
            elif hour >= 22:
                score = 0.6
            # Early morning / late evening
            elif hour < 6 or hour >= 20:
                score = 0.3
            # Normal business hours
            else:
                score = 0.0

            # Weekend bump
            if weekday >= 5:
                score = min(score + 0.2, 1.0)

            return score
        except Exception:
            return 0.0

    def _geo_risk_score(self, entry: dict) -> float:
        """Score based on IP reputation heuristic (0-1).

        Uses a simple heuristic: private (RFC 1918) IPs are considered
        low-risk (internal traffic), while public IPs receive a base score.
        IPs that cannot be parsed receive a neutral score.
        """
        source_ip = entry.get('source_ip')
        if not source_ip:
            return 0.0

        try:
            addr = ipaddress.ip_address(source_ip)

            # Loopback → no risk
            if addr.is_loopback:
                return 0.0

            # Private / internal → low risk
            if addr.is_private:
                return 0.1

            # Link-local → low risk
            if addr.is_link_local:
                return 0.05

            # Reserved → moderate suspicion
            if addr.is_reserved:
                return 0.4

            # Public IP → base risk
            # In a production system this would query threat-intelligence feeds.
            return 0.5

        except (ValueError, TypeError):
            # Unparseable IP – moderate uncertainty
            return 0.3
