"""
Linux auth.log parser for the Cybersecurity Log Analysis Platform.

Parses PAM authentication events, ``sudo`` command invocations, and ``su``
session transitions from the standard syslog format used by
``/var/log/auth.log``.
"""

import re
from typing import Optional

from .base import BaseParser


class AuthParser(BaseParser):
    """Parser for Linux ``auth.log`` files.

    Expected line format::

        Mon DD HH:MM:SS hostname service[pid]: message

    Detected event types:
        - ``LOGIN_SUCCESS`` / ``LOGIN_FAILED`` — PAM session events
        - ``AUTH_FAILURE`` — explicit authentication failures
        - ``SUDO`` — sudo command invocations
        - ``SU`` — su session open / close
        - ``SESSION_OPEN`` / ``SESSION_CLOSE`` — generic PAM session events
    """

    name = 'auth'

    # Main syslog line pattern
    SYSLOG_RE = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$'
    )

    # Message-level patterns
    _AUTH_FAILURE_RE = re.compile(
        r'authentication failure.*?rhost=([\d.]+)(?:.*?user=(\w+))?', re.IGNORECASE,
    )
    _PAM_FAILURE_RE = re.compile(
        r'pam_unix\(\S+:auth\):\s+authentication failure.*?rhost=([\d.]+)(?:.*?user=(\w+))?',
        re.IGNORECASE,
    )
    _ACCEPTED_RE = re.compile(
        r'Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([\d.]+)', re.IGNORECASE,
    )
    _FAILED_PASSWORD_RE = re.compile(
        r'Failed\s+password\s+for\s+(invalid user\s+)?(\S+)\s+from\s+([\d.]+)',
        re.IGNORECASE,
    )
    _SUDO_RE = re.compile(
        r'(\S+)\s*:\s*.*?COMMAND=(.*)', re.IGNORECASE,
    )
    _SU_SESSION_RE = re.compile(
        r"pam_unix\(su\S*:session\):\s+session\s+(opened|closed)\s+for\s+user\s+(\S+)(?:\s+by\s+(\S+))?",
        re.IGNORECASE,
    )
    _SESSION_RE = re.compile(
        r'pam_unix\((\S+):session\):\s+session\s+(opened|closed)\s+for\s+user\s+(\S+)',
        re.IGNORECASE,
    )
    _RHOST_RE = re.compile(r'rhost=([\d.]+)')
    _FROM_IP_RE = re.compile(r'from\s+([\d.]+)')

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single ``auth.log`` line.

        Args:
            line: Raw log line.

        Returns:
            Structured dict or ``None``.
        """
        if not line or not line.strip():
            return None

        line = line.strip()

        try:
            match = self.SYSLOG_RE.match(line)
            if not match:
                return None

            timestamp_str = match.group(1)
            hostname = match.group(2)
            service = match.group(3)
            pid = match.group(4)
            message = match.group(5)

            timestamp = self._parse_timestamp(timestamp_str)

            source_ip = None
            action = 'AUTH_EVENT'
            user = None
            severity = 'info'
            extra_meta: dict = {}

            # --- Classify the message ---

            # Failed password
            m = self._FAILED_PASSWORD_RE.search(message)
            if m:
                is_invalid = bool(m.group(1))
                user = m.group(2)
                source_ip = m.group(3)
                action = 'LOGIN_FAILED'
                severity = 'medium'
                if is_invalid:
                    extra_meta['invalid_user'] = True
                    action = 'INVALID_USER'

            # Accepted login
            if action == 'AUTH_EVENT':
                m = self._ACCEPTED_RE.search(message)
                if m:
                    auth_method = m.group(1)
                    user = m.group(2)
                    source_ip = m.group(3)
                    action = 'LOGIN_SUCCESS'
                    severity = 'low'
                    extra_meta['auth_method'] = auth_method

            # PAM authentication failure
            if action == 'AUTH_EVENT':
                m = self._PAM_FAILURE_RE.search(message) or self._AUTH_FAILURE_RE.search(message)
                if m:
                    source_ip = m.group(1)
                    user = m.group(2) if m.lastindex >= 2 else None
                    action = 'AUTH_FAILURE'
                    severity = 'medium'

            # sudo command
            if action == 'AUTH_EVENT' and 'sudo' in service.lower():
                m = self._SUDO_RE.search(message)
                if m:
                    user = m.group(1)
                    command = m.group(2).strip()
                    action = 'SUDO'
                    severity = 'low'
                    extra_meta['command'] = command
                    # Flag dangerous sudo commands
                    dangerous_cmds = ['rm -rf', 'chmod 777', 'passwd', 'visudo',
                                      'shutdown', 'reboot', '/bin/bash', '/bin/sh']
                    if any(dc in command.lower() for dc in dangerous_cmds):
                        severity = 'high'
                        extra_meta['suspicious_command'] = True

            # su session
            if action == 'AUTH_EVENT':
                m = self._SU_SESSION_RE.search(message)
                if m:
                    state = m.group(1).lower()  # opened / closed
                    user = m.group(2)
                    by_user = m.group(3)
                    action = 'SU'
                    severity = 'low'
                    extra_meta['session_state'] = state
                    if by_user:
                        extra_meta['by_user'] = by_user

            # Generic session open/close
            if action == 'AUTH_EVENT':
                m = self._SESSION_RE.search(message)
                if m:
                    pam_service = m.group(1)
                    state = m.group(2).lower()
                    user = m.group(3)
                    action = f'SESSION_{state.upper()}'
                    severity = 'info'
                    extra_meta['pam_service'] = pam_service

            # Fall back to extracting IP from message
            if source_ip is None:
                m = self._RHOST_RE.search(message)
                if m:
                    source_ip = m.group(1)
                else:
                    m = self._FROM_IP_RE.search(message)
                    if m:
                        source_ip = m.group(1)

            metadata = {
                'hostname': hostname,
                'service': service,
                'pid': pid,
                'user': user,
                'message': message,
                **extra_meta,
            }

            description = f'[{service}] {action}: {message[:150]}'

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
        """Return confidence that lines match the auth.log syslog format.

        Also checks for auth-specific keywords to avoid false positives from
        other syslog-format logs.

        Args:
            sample_lines: A list of raw log lines.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not sample_lines:
            return 0.0

        auth_keywords = re.compile(
            r'(sshd|sudo|su\[|pam_unix|authentication failure|Accepted\s+password|'
            r'Failed\s+password|session opened|session closed)',
            re.IGNORECASE,
        )

        syslog_matches = 0
        keyword_matches = 0
        total = 0

        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            total += 1
            if self.SYSLOG_RE.match(line):
                syslog_matches += 1
                if auth_keywords.search(line):
                    keyword_matches += 1

        if total == 0:
            return 0.0

        # Require syslog format AND auth-specific keywords
        syslog_ratio = syslog_matches / total
        keyword_ratio = keyword_matches / total if syslog_matches else 0.0
        return syslog_ratio * 0.4 + keyword_ratio * 0.6
