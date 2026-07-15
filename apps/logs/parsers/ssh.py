"""
SSH (sshd) log parser for the Cybersecurity Log Analysis Platform.

Parses ``sshd`` messages from the syslog format and classifies them into
authentication successes, failures, brute-force patterns, invalid user
attempts, and connection lifecycle events.
"""

import re
from typing import Optional

from .base import BaseParser


class SSHParser(BaseParser):
    """Parser for OpenSSH ``sshd`` log entries.

    Expected input format (syslog)::

        Mon DD HH:MM:SS hostname sshd[pid]: message

    Detected event types:
        - ``LOGIN_FAILED`` — failed password authentication
        - ``LOGIN_SUCCESS`` — accepted password authentication
        - ``KEY_AUTH_SUCCESS`` — accepted public-key authentication
        - ``INVALID_USER`` — connection attempt with a non-existent user
        - ``CONNECTION_CLOSED`` — connection closed by remote host
        - ``DISCONNECT`` — disconnected from remote host
        - ``AUTH_LIMIT_EXCEEDED`` — too many authentication failures
    """

    name = 'ssh'

    # Syslog prefix
    SYSLOG_RE = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+(.+)$'
    )

    # Message patterns
    _FAILED_PASSWORD_RE = re.compile(
        r'Failed password for (invalid user )?(\S+) from ([\d.]+) port (\d+)'
    )
    _ACCEPTED_PASSWORD_RE = re.compile(
        r'Accepted password for (\S+) from ([\d.]+) port (\d+)'
    )
    _ACCEPTED_KEY_RE = re.compile(
        r'Accepted publickey for (\S+) from ([\d.]+) port (\d+)'
    )
    _INVALID_USER_RE = re.compile(
        r'Invalid user (\S+) from ([\d.]+)(?:\s+port\s+(\d+))?'
    )
    _CONNECTION_CLOSED_RE = re.compile(
        r'Connection closed by (?:authenticating user \S+ )?([\d.]+) port (\d+)'
    )
    _DISCONNECTED_RE = re.compile(
        r'Disconnected from (?:user \S+ )?([\d.]+) port (\d+)'
    )
    _DISCONNECT_SIMPLE_RE = re.compile(
        r'Disconnected from ([\d.]+)'
    )
    _AUTH_LIMIT_RE = re.compile(
        r'(Too many authentication failures|maximum authentication attempts exceeded)',
        re.IGNORECASE,
    )
    _AUTH_LIMIT_IP_RE = re.compile(
        r'from ([\d.]+)'
    )
    _CONNECTION_RESET_RE = re.compile(
        r'Connection reset by ([\d.]+) port (\d+)'
    )
    _RECEIVED_DISCONNECT_RE = re.compile(
        r'Received disconnect from ([\d.]+) port (\d+)'
    )

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single sshd log line.

        Args:
            line: Raw log line.

        Returns:
            Structured dict or ``None``.
        """
        if not line or not line.strip():
            return None

        line = line.strip()

        try:
            syslog_match = self.SYSLOG_RE.match(line)
            if not syslog_match:
                return None

            timestamp_str = syslog_match.group(1)
            hostname = syslog_match.group(2)
            pid = syslog_match.group(3)
            message = syslog_match.group(4)

            timestamp = self._parse_timestamp(timestamp_str)

            source_ip = None
            action = 'SSH_EVENT'
            user = None
            port = None
            severity = 'info'
            extra_meta: dict = {}

            # --- Failed password ---
            m = self._FAILED_PASSWORD_RE.search(message)
            if m:
                is_invalid = bool(m.group(1))
                user = m.group(2)
                source_ip = m.group(3)
                port = m.group(4)
                action = 'LOGIN_FAILED'
                severity = 'medium'
                if is_invalid:
                    extra_meta['invalid_user'] = True

            # --- Accepted password ---
            if action == 'SSH_EVENT':
                m = self._ACCEPTED_PASSWORD_RE.search(message)
                if m:
                    user = m.group(1)
                    source_ip = m.group(2)
                    port = m.group(3)
                    action = 'LOGIN_SUCCESS'
                    severity = 'low'

            # --- Accepted public key ---
            if action == 'SSH_EVENT':
                m = self._ACCEPTED_KEY_RE.search(message)
                if m:
                    user = m.group(1)
                    source_ip = m.group(2)
                    port = m.group(3)
                    action = 'KEY_AUTH_SUCCESS'
                    severity = 'info'

            # --- Invalid user ---
            if action == 'SSH_EVENT':
                m = self._INVALID_USER_RE.search(message)
                if m:
                    user = m.group(1)
                    source_ip = m.group(2)
                    port = m.group(3)
                    action = 'INVALID_USER'
                    severity = 'medium'

            # --- Connection closed ---
            if action == 'SSH_EVENT':
                m = self._CONNECTION_CLOSED_RE.search(message)
                if m:
                    source_ip = m.group(1)
                    port = m.group(2)
                    action = 'CONNECTION_CLOSED'
                    severity = 'info'

            # --- Connection reset ---
            if action == 'SSH_EVENT':
                m = self._CONNECTION_RESET_RE.search(message)
                if m:
                    source_ip = m.group(1)
                    port = m.group(2)
                    action = 'CONNECTION_RESET'
                    severity = 'low'

            # --- Received disconnect ---
            if action == 'SSH_EVENT':
                m = self._RECEIVED_DISCONNECT_RE.search(message)
                if m:
                    source_ip = m.group(1)
                    port = m.group(2)
                    action = 'DISCONNECT'
                    severity = 'info'

            # --- Disconnected ---
            if action == 'SSH_EVENT':
                m = self._DISCONNECTED_RE.search(message) or self._DISCONNECT_SIMPLE_RE.search(message)
                if m:
                    source_ip = m.group(1)
                    port = m.group(2) if m.lastindex >= 2 else None
                    action = 'DISCONNECT'
                    severity = 'info'

            # --- Auth limit exceeded ---
            if action == 'SSH_EVENT':
                m = self._AUTH_LIMIT_RE.search(message)
                if m:
                    action = 'AUTH_LIMIT_EXCEEDED'
                    severity = 'high'
                    ip_m = self._AUTH_LIMIT_IP_RE.search(message)
                    if ip_m:
                        source_ip = ip_m.group(1)

            metadata = {
                'hostname': hostname,
                'pid': pid,
                'user': user,
                'port': port,
                'message': message,
                **extra_meta,
            }

            description = f'[sshd] {action}: {message[:150]}'

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
        """Return confidence that lines match SSH log format.

        Looks for the ``sshd[PID]:`` pattern in syslog lines.

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
            if self.SYSLOG_RE.match(line):
                matches += 1

        return matches / total if total > 0 else 0.0
