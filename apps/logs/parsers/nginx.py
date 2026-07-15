"""
Nginx log parser for the Cybersecurity Log Analysis Platform.

Handles both the Nginx default access log format and the Nginx error log
format.  Shares many heuristics with the Apache parser but adds support for
the ``$http_x_forwarded_for`` field and the structured error log layout.
"""

import re
from typing import Optional

from .base import BaseParser


class NginxParser(BaseParser):
    """Parser for Nginx access and error logs.

    Access log format::

        $remote_addr - $remote_user [$time_local] "$request"
        $status $body_bytes_sent "$http_referer" "$http_x_forwarded_for"

    Error log format::

        YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message, client: IP, ...
    """

    name = 'nginx'

    # Nginx access log (note: last quoted field is x_forwarded_for, not user_agent)
    ACCESS_RE = re.compile(
        r'^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
    )

    # Nginx error log
    ERROR_RE = re.compile(
        r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*?(\d+)? ?(.+)'
    )
    ERROR_CLIENT_RE = re.compile(r'client:\s+([\d.]+)')
    ERROR_SERVER_RE = re.compile(r'server:\s+(\S+)')
    ERROR_REQUEST_RE = re.compile(r'request:\s+"([^"]*)"')

    # Attack-pattern signatures
    _SQLI_PATTERNS = re.compile(
        r'(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*select\s+|'
        r'benchmark\s*\(|sleep\s*\(|concat\s*\(|load_file)',
        re.IGNORECASE,
    )
    _TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.IGNORECASE)
    _XSS_PATTERN = re.compile(r'(<script|%3cscript|javascript:|onerror\s*=)', re.IGNORECASE)

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single Nginx log line (access or error format).

        Args:
            line: Raw log line string.

        Returns:
            Structured dict or ``None`` if the line is unparseable.
        """
        if not line or not line.strip():
            return None

        line = line.strip()

        try:
            # Try access log first
            result = self._parse_access(line)
            if result:
                return result

            # Fall back to error log
            return self._parse_error(line)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Access log handling
    # ------------------------------------------------------------------

    def _parse_access(self, line: str) -> Optional[dict]:
        """Parse an Nginx access log line."""
        match = self.ACCESS_RE.match(line)
        if not match:
            return None

        source_ip = match.group(1)
        timestamp_str = match.group(2)
        method = match.group(3)
        url = match.group(4)
        status_code = int(match.group(5))
        size_str = match.group(6)
        size = int(size_str) if size_str != '-' else 0
        referer = match.group(7)
        forwarded_for = match.group(8)

        timestamp = self._parse_timestamp(timestamp_str)

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

        metadata = {
            'method': method,
            'url': url,
            'status_code': status_code,
            'size': size,
            'referer': referer,
            'x_forwarded_for': forwarded_for,
        }
        if attack_type:
            metadata['attack_type'] = attack_type

        severity = self._assign_severity(action, status_code=status_code, metadata=metadata)
        if attack_type in ('sql_injection', 'xss'):
            severity = 'critical'
        elif attack_type == 'directory_traversal':
            severity = 'high'

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

    # ------------------------------------------------------------------
    # Error log handling
    # ------------------------------------------------------------------

    def _parse_error(self, line: str) -> Optional[dict]:
        """Parse an Nginx error log line."""
        match = self.ERROR_RE.match(line)
        if not match:
            return None

        timestamp_str = match.group(1)
        level = match.group(2)
        message = match.group(6)

        timestamp = self._parse_timestamp(timestamp_str)

        client_match = self.ERROR_CLIENT_RE.search(message)
        source_ip = client_match.group(1) if client_match else None

        server_match = self.ERROR_SERVER_RE.search(message)
        server = server_match.group(1) if server_match else None

        request_match = self.ERROR_REQUEST_RE.search(message)
        request = request_match.group(1) if request_match else None

        action = f'NGINX_ERROR_{level.upper()}'

        severity_map = {
            'emerg': 'critical',
            'alert': 'critical',
            'crit': 'critical',
            'error': 'high',
            'warn': 'medium',
            'notice': 'low',
            'info': 'info',
            'debug': 'info',
        }
        severity = severity_map.get(level.lower(), 'medium')

        metadata = {
            'level': level,
            'server': server,
            'request': request,
            'message': message.strip(),
        }

        description = f'Nginx [{level}] {message[:120]}'

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

    def detect_format(self, sample_lines: list[str]) -> float:
        """Return confidence that the lines match Nginx format.

        Gives a slight bias towards error-log detection so that mixed
        Nginx logs still score highly.

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
            if self.ACCESS_RE.match(line) or self.ERROR_RE.match(line):
                matches += 1
        return matches / total if total > 0 else 0.0
