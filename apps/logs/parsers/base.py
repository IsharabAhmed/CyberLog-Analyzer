"""
Base parser module for the Cybersecurity Log Analysis Platform.

Provides the abstract base class that all log format parsers must inherit from,
along with shared utility methods for severity classification and timestamp parsing.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
import re


class BaseParser(ABC):
    """Abstract base class for log parsers.

    All concrete parser implementations must inherit from this class and
    implement the ``parse_line`` and ``detect_format`` methods.

    Attributes:
        name: A human-readable identifier for this parser type.
    """

    name: str = 'base'

    @abstractmethod
    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single log line into a structured dictionary.

        Args:
            line: A single line of log text.

        Returns:
            A dictionary with the following keys if parsing succeeds:
                - timestamp (str or datetime)
                - source_ip (str or None)
                - destination_ip (str or None)
                - action (str)
                - severity (str): one of critical/high/medium/low/info
                - description (str)
                - raw_line (str)
                - metadata (dict)
            Returns ``None`` if the line cannot be parsed.
        """
        pass

    @abstractmethod
    def detect_format(self, sample_lines: list[str]) -> float:
        """Return a confidence score that the given lines match this format.

        Args:
            sample_lines: A list of raw log lines to evaluate.

        Returns:
            A float between 0.0 (no match) and 1.0 (perfect match).
        """
        pass

    def _assign_severity(self, action: str, status_code: int = 0, metadata: dict = None) -> str:
        """Assign a severity level based on action keywords and HTTP status codes.

        The severity hierarchy is: critical > high > medium > low > info.

        Args:
            action: The action string extracted from the log line.
            status_code: An optional HTTP status code for web-server logs.
            metadata: Optional metadata dict; if ``repeated`` is True the
                severity may be escalated.

        Returns:
            A severity string.
        """
        action_upper = action.upper()

        if any(kw in action_upper for kw in ['ATTACK', 'EXPLOIT', 'INJECTION', 'CRITICAL']):
            return 'critical'
        elif any(kw in action_upper for kw in ['FAILED', 'DENIED', 'DROP', 'REJECT', 'BLOCK', 'INVALID']):
            return 'high' if metadata and metadata.get('repeated', False) else 'medium'
        elif any(kw in action_upper for kw in ['WARNING', 'TIMEOUT', 'ERROR']):
            return 'medium'
        elif any(kw in action_upper for kw in ['ACCEPT', 'SUCCESS', 'ALLOW']):
            return 'low'
        elif status_code >= 500:
            return 'high'
        elif status_code >= 400:
            return 'medium'
        return 'info'

    def _parse_timestamp(self, timestamp_str: str, formats: list[str] = None) -> Optional[datetime]:
        """Attempt to parse a timestamp string using multiple format patterns.

        Args:
            timestamp_str: The raw timestamp string extracted from a log line.
            formats: An optional list of ``strftime``-compatible format strings
                to try.  If ``None``, a set of common log-format patterns is
                used.

        Returns:
            A ``datetime`` object on success, or ``None`` if no format matched.
        """
        if formats is None:
            formats = [
                '%d/%b/%Y:%H:%M:%S %z',   # Apache / Nginx access log
                '%b %d %H:%M:%S',           # Syslog (no year)
                '%Y-%m-%dT%H:%M:%S%z',      # ISO 8601
                '%Y-%m-%d %H:%M:%S',         # Generic datetime
                '%b %d %Y %H:%M:%S',         # Auth log variant
                '%Y/%m/%d %H:%M:%S',         # Nginx error log
            ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.strip(), fmt)
                # Syslog format omits the year; assume the current year.
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        return None
