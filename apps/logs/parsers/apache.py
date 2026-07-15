"""
Apache log parser for the Cybersecurity Log Analysis Platform.

Handles both the Apache Combined Log Format and the Common Log Format as a
fallback.  Includes heuristic detection of SQL injection and directory
traversal attack patterns embedded in request URLs.
"""

import re
from typing import Optional

from .base import BaseParser


class ApacheParser(BaseParser):
    """Parser for Apache HTTP Server access logs.

    Supports:
        - **Combined Log Format**:
          ``%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"``
        - **Common Log Format** (fallback):
          ``%h %l %u %t "%r" %>s %b``
    """

    name = 'apache'

    # Combined Log Format
    COMBINED_RE = re.compile(
        r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
    )

    # Common Log Format (no referer / user-agent)
    COMMON_RE = re.compile(
        r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-)'
    )

    # Attack-pattern signatures in request URLs
    _SQLI_PATTERNS = re.compile(
        r'(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*select\s+|'
        r'benchmark\s*\(|sleep\s*\(|concat\s*\(|load_file)',
        re.IGNORECASE,
    )
    _TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.IGNORECASE)
    _XSS_PATTERN = re.compile(r'(<script|%3cscript|javascript:|onerror\s*=)', re.IGNORECASE)

    # Suspicious user-agent substrings (scanners / exploit tools)
    _SCANNER_AGENTS = re.compile(
        r'(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|burpsuite)',
        re.IGNORECASE,
    )

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single Apache access-log line.

        Args:
            line: Raw log line string.

        Returns:
            Structured dict or ``None`` if the line is unparseable.
        """
        if not line or not line.strip():
            return None

        line = line.strip()

        try:
            match = self.COMBINED_RE.match(line)
            is_combined = True
            if not match:
                match = self.COMMON_RE.match(line)
                is_combined = False
            if not match:
                return None

            source_ip = match.group(1)
            timestamp_str = match.group(2)
            method = match.group(3)
            url = match.group(4)
            status_code = int(match.group(5))
            size_str = match.group(6)
            size = int(size_str) if size_str != '-' else 0
            referer = match.group(7) if is_combined else '-'
            user_agent = match.group(8) if is_combined else '-'

            timestamp = self._parse_timestamp(timestamp_str)

            # Determine the action / attack classification
            action = method
            attack_type = None

            if self._SQLI_PATTERNS.search(url):
                action = f'{method}_INJECTION'
                attack_type = 'sql_injection'
            elif self._TRAVERSAL_PATTERN.search(url):
                action = f'{method}_TRAVERSAL'
                attack_type = 'directory_traversal'
            elif self._XSS_PATTERN.search(url):
                action = f'{method}_XSS'
                attack_type = 'xss'
            elif self._SCANNER_AGENTS.search(user_agent):
                action = f'{method}_SCANNER'
                attack_type = 'scanner'

            metadata = {
                'method': method,
                'url': url,
                'status_code': status_code,
                'size': size,
                'referer': referer,
                'user_agent': user_agent,
            }
            if attack_type:
                metadata['attack_type'] = attack_type

            severity = self._assign_severity(action, status_code=status_code, metadata=metadata)

            # Escalate known attack patterns
            if attack_type in ('sql_injection', 'xss'):
                severity = 'critical'
            elif attack_type == 'directory_traversal':
                severity = 'high'
            elif attack_type == 'scanner':
                severity = max('medium', severity, key=lambda s: ['info', 'low', 'medium', 'high', 'critical'].index(s))

            description = f'{method} {url} - Status {status_code}'

            return {
                'timestamp': timestamp or timestamp_str,
                'source_ip': source_ip,
                'destination_ip': None,
                'action': action,
                'severity': severity,
                'description': description,
                'raw_line': line,
                'metadata': metadata,
            }

        except Exception:
            return None

    def detect_format(self, sample_lines: list[str]) -> float:
        """Return the fraction of *sample_lines* that match the Apache format.

        Args:
            sample_lines: A list of raw log lines.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not sample_lines:
            return 0.0

        matches = 0
        total = 0
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            total += 1
            if self.COMBINED_RE.match(line) or self.COMMON_RE.match(line):
                matches += 1
        return matches / total if total > 0 else 0.0
