"""
Parser registry and auto-detection for the Cybersecurity Log Analysis Platform.

This module exposes a ``PARSER_MAP`` of all available parsers, a convenience
``get_parser`` factory, and a ``detect_log_type`` function that evaluates every
registered parser against a set of sample lines and returns the best match.
"""

from .apache import ApacheParser
from .nginx import NginxParser
from .auth import AuthParser
from .firewall import FirewallParser
from .ssh import SSHParser

__all__ = [
    'ApacheParser',
    'NginxParser',
    'AuthParser',
    'FirewallParser',
    'SSHParser',
    'PARSER_MAP',
    'get_parser',
    'detect_log_type',
]

PARSER_MAP = {
    'apache': ApacheParser,
    'nginx': NginxParser,
    'auth': AuthParser,
    'firewall': FirewallParser,
    'ssh': SSHParser,
}


def get_parser(log_type: str):
    """Return an instantiated parser for the given *log_type*.

    Falls back to ``ApacheParser`` when the requested type is unknown.

    Args:
        log_type: One of the keys in ``PARSER_MAP``.

    Returns:
        An instance of the corresponding parser.
    """
    return PARSER_MAP.get(log_type, ApacheParser)()


def detect_log_type(sample_lines: list[str]) -> str:
    """Auto-detect the log type by scoring every registered parser.

    Each parser's ``detect_format`` method is called with the sample lines.
    The parser that returns the highest confidence score wins.

    Args:
        sample_lines: A list of raw log lines to evaluate.

    Returns:
        The key from ``PARSER_MAP`` corresponding to the best-matching parser.
        Defaults to ``'apache'`` when no parser produces a positive score.
    """
    best_type = 'apache'
    best_score = 0.0
    for log_type, parser_class in PARSER_MAP.items():
        parser = parser_class()
        score = parser.detect_format(sample_lines)
        if score > best_score:
            best_score = score
            best_type = log_type
    return best_type
