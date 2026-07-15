"""
Firewall log parser for the Cybersecurity Log Analysis Platform.

Handles UFW (Uncomplicated Firewall) and raw iptables log formats, both of
which typically arrive via syslog.  Extracts source/destination IPs, ports,
protocols, and the firewall action (BLOCK, ALLOW, DROP, etc.).
"""

import re
from typing import Optional

from .base import BaseParser


# Well-known ports for enrichment
_WELL_KNOWN_PORTS = {
    '21': 'FTP',
    '22': 'SSH',
    '23': 'Telnet',
    '25': 'SMTP',
    '53': 'DNS',
    '80': 'HTTP',
    '110': 'POP3',
    '143': 'IMAP',
    '443': 'HTTPS',
    '445': 'SMB',
    '993': 'IMAPS',
    '995': 'POP3S',
    '1433': 'MSSQL',
    '3306': 'MySQL',
    '3389': 'RDP',
    '5432': 'PostgreSQL',
    '5900': 'VNC',
    '6379': 'Redis',
    '8080': 'HTTP-Alt',
    '8443': 'HTTPS-Alt',
    '27017': 'MongoDB',
}


class FirewallParser(BaseParser):
    """Parser for UFW and iptables firewall logs.

    UFW lines look like::

        Mar 15 10:23:01 server kernel: [UFW BLOCK] IN=eth0 ...
        SRC=10.0.0.5 DST=192.168.1.1 ... PROTO=TCP SPT=54321 DPT=22

    iptables lines share the same key=value pair structure but may omit
    the ``[UFW ...]`` tag.
    """

    name = 'firewall'

    # Syslog prefix (timestamp + hostname + kernel tag)
    SYSLOG_PREFIX_RE = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*(?:\[\s*[\d.]+\]\s*)?(.+)$'
    )

    # UFW action tag
    UFW_ACTION_RE = re.compile(r'\[UFW\s+(\w+)\]')

    # Key=value fields common to both UFW and iptables output
    _SRC_RE = re.compile(r'SRC=([\d.]+)')
    _DST_RE = re.compile(r'DST=([\d.]+)')
    _PROTO_RE = re.compile(r'PROTO=(\w+)')
    _SPT_RE = re.compile(r'SPT=(\d+)')
    _DPT_RE = re.compile(r'DPT=(\d+)')
    _IN_RE = re.compile(r'IN=(\S*)')
    _OUT_RE = re.compile(r'OUT=(\S*)')
    _MAC_RE = re.compile(r'MAC=(\S+)')
    _LEN_RE = re.compile(r'LEN=(\d+)')
    _TTL_RE = re.compile(r'TTL=(\d+)')

    # iptables log with action in the prefix (e.g., "iptables DROP: ...")
    IPTABLES_ACTION_RE = re.compile(r'(ACCEPT|DROP|REJECT|LOG|BLOCK|ALLOW)')

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single firewall log line.

        Args:
            line: Raw log line.

        Returns:
            Structured dict or ``None``.
        """
        if not line or not line.strip():
            return None

        line = line.strip()

        try:
            # Extract syslog prefix
            syslog_match = self.SYSLOG_PREFIX_RE.match(line)
            if syslog_match:
                timestamp_str = syslog_match.group(1)
                hostname = syslog_match.group(2)
                payload = syslog_match.group(3)
            else:
                # Try to parse without strict syslog prefix
                timestamp_str = None
                hostname = None
                payload = line

            # Need at least SRC and DST to be useful
            src_match = self._SRC_RE.search(payload)
            dst_match = self._DST_RE.search(payload)
            if not src_match or not dst_match:
                return None

            source_ip = src_match.group(1)
            destination_ip = dst_match.group(1)

            proto_match = self._PROTO_RE.search(payload)
            protocol = proto_match.group(1) if proto_match else 'UNKNOWN'

            spt_match = self._SPT_RE.search(payload)
            dpt_match = self._DPT_RE.search(payload)
            src_port = spt_match.group(1) if spt_match else None
            dst_port = dpt_match.group(1) if dpt_match else None

            in_match = self._IN_RE.search(payload)
            out_match = self._OUT_RE.search(payload)
            in_iface = in_match.group(1) if in_match else None
            out_iface = out_match.group(1) if out_match else None

            len_match = self._LEN_RE.search(payload)
            ttl_match = self._TTL_RE.search(payload)
            pkt_len = int(len_match.group(1)) if len_match else None
            ttl = int(ttl_match.group(1)) if ttl_match else None

            # Determine action
            ufw_match = self.UFW_ACTION_RE.search(payload)
            if ufw_match:
                action = ufw_match.group(1).upper()
            else:
                ipt_match = self.IPTABLES_ACTION_RE.search(payload)
                action = ipt_match.group(1).upper() if ipt_match else 'LOG'

            timestamp = self._parse_timestamp(timestamp_str) if timestamp_str else None

            # Severity assignment
            severity_map = {
                'BLOCK': 'medium',
                'DROP': 'medium',
                'REJECT': 'medium',
                'LIMIT': 'high',
                'ALLOW': 'info',
                'ACCEPT': 'info',
                'LOG': 'info',
            }
            severity = severity_map.get(action, 'medium')

            # Enrich destination port with service name
            service = _WELL_KNOWN_PORTS.get(dst_port, '') if dst_port else ''

            metadata = {
                'hostname': hostname,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'service': service,
                'in_interface': in_iface,
                'out_interface': out_iface,
                'packet_length': pkt_len,
                'ttl': ttl,
            }

            port_info = f':{dst_port}' if dst_port else ''
            svc_info = f' ({service})' if service else ''
            description = (
                f'{action} {protocol} {source_ip}:{src_port or "?"} -> '
                f'{destination_ip}{port_info}{svc_info}'
            )

            return {
                'timestamp': timestamp or timestamp_str or '',
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'action': action,
                'severity': severity,
                'description': description,
                'raw_line': line,
                'metadata': metadata,
            }

        except Exception:
            return None

    def detect_format(self, sample_lines: list[str]) -> float:
        """Return confidence that lines match firewall log format.

        Looks for the presence of ``SRC=``, ``DST=``, and ``PROTO=`` tokens
        that are hallmarks of iptables / UFW output.

        Args:
            sample_lines: A list of raw log lines.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not sample_lines:
            return 0.0

        fw_pattern = re.compile(r'SRC=[\d.]+.*DST=[\d.]+.*PROTO=\w+')

        matches = 0
        total = 0
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            total += 1
            if fw_pattern.search(line):
                matches += 1

        return matches / total if total > 0 else 0.0
