"""
LogGuardian AI Parser Module.
Parses various log types (Apache/Nginx, SSH, Linux auth, Firewall, Syslog)
and normalizes them into a unified LogEntry structure.
"""

import os
import re
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple
from logger import log
from utils import parse_timestamp

@dataclass
class LogEntry:
    """Dataclass holding standardized, normalized log fields."""
    timestamp: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    method: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    raw_line: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts the LogEntry to a standard dictionary."""
        return asdict(self)

class LogParser:
    """
    Standard parser that auto-detects or accepts log format specifications,
    and returns a collection of normalized LogEntry elements.
    """

    # Regex definitions for parsing
    # 1. Apache/Nginx Combined/Common Access Log Regex
    ACCESS_LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )

    # 2. Apache Error Log Regex
    # [Sun May 17 10:05:03.123456 2026] [ssl:warn] [pid 1234] [client 192.168.1.100:51234] message...
    APACHE_ERROR_REGEX = re.compile(
        r'^\[(?P<time>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+(?:\[pid\s+[^\]]+\]\s+)?'
        r'\[client\s+(?P<ip>[^\]:]+)(?::\d+)?\]\s+(?P<message>.*)$'
    )

    # 3. Linux auth.log / SSH log Regex
    # May 17 10:05:03 ubuntu sshd[1234]: Failed password for root from 192.168.1.102 port 45672 ssh2
    # May 17 10:05:05 ubuntu sshd[1234]: Invalid user admin from 192.168.1.100 port 45312
    # May 17 10:05:06 ubuntu sudo:    aswin : TTY=pts/1 ; PWD=/home/aswin ; USER=root ; COMMAND=/bin/bash
    AUTH_LOG_REGEX = re.compile(
        r'^(?P<time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
        r'(?P<process>sshd|sudo|auth)\[?(?P<pid>\d*)\]?:\s+(?P<message>.*)$'
    )

    # 4. UFW / Iptables Firewall Log Regex
    # May 17 10:05:03 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 LEN=40 PROTO=TCP SPT=51234 DPT=80
    IPTABLES_REGEX = re.compile(
        r'^(?P<time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+kernel:.*'
        r'SRC=(?P<src_ip>[^\s]+)\s+DST=(?P<dst_ip>[^\s]+).*'
        r'PROTO=(?P<proto>[^\s]+)(?:\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+))?'
    )

    # 5. Generic IP extractor for Custom Logs
    IP_EXTRACTOR = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    # 6. Generic Date extractor
    DATE_EXTRACTOR = re.compile(
        r'\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\b'
    )

    @classmethod
    def detect_format(cls, lines: List[str]) -> str:
        """
        Scans sample lines from the log file to auto-detect its type.
        
        Args:
            lines: Sample lines from the file.
            
        Returns:
            A string identifier of the log type.
        """
        if not lines:
            return "custom"

        # Check top 10 non-empty lines
        sample = [line.strip() for line in lines if line.strip()][:10]
        
        score = {"apache_nginx_access": 0, "apache_error": 0, "linux_auth": 0, "firewall_iptables": 0}

        for line in sample:
            if cls.ACCESS_LOG_REGEX.match(line):
                score["apache_nginx_access"] += 1
            if cls.APACHE_ERROR_REGEX.match(line):
                score["apache_error"] += 1
            if cls.AUTH_LOG_REGEX.match(line) or "sshd[" in line or "pam_unix" in line:
                score["linux_auth"] += 1
            if "SRC=" in line and "DST=" in line and "PROTO=" in line:
                score["firewall_iptables"] += 1

        best_fit = max(score, key=score.get)
        if score[best_fit] > 0:
            log.info(f"Auto-detected log format: {best_fit} (Confidence: {score[best_fit]}/{len(sample)})")
            return best_fit

        log.info("Auto-detect failed. Defaulting to custom plain text parser.")
        return "custom"

    def parse(self, filepath: str, log_type: Optional[str] = None) -> List[LogEntry]:
        """
        Reads a log file, normalizes entries, and returns LogEntry collection.
        
        Args:
            filepath: Path to the log file.
            log_type: Forced log type. If None, it runs auto-detection.
            
        Returns:
            A list of normalized LogEntry objects.
        """
        if not os.path.exists(filepath):
            log.error(f"Log file not found: {filepath}")
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            log.error(f"Error reading file {filepath}: {e}")
            return []

        if not log_type or log_type == "auto":
            log_type = self.detect_format(lines)

        normalized_entries: List[LogEntry] = []

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            entry = self._parse_line(line_str, log_type)
            if entry:
                normalized_entries.append(entry)

        log.info(f"Successfully parsed {len(normalized_entries)} entries from '{os.path.basename(filepath)}' as '{log_type}'.")
        return normalized_entries

    def _parse_line(self, line: str, log_type: str) -> Optional[LogEntry]:
        """Helper to parse a single line based on log_type."""
        try:
            if log_type == "apache_nginx_access":
                match = self.ACCESS_LOG_REGEX.match(line)
                if match:
                    gd = match.groupdict()
                    size = gd.get("size")
                    resp_size = int(size) if size and size.isdigit() else 0
                    
                    # Try to extract username if present (e.g., from auth_basic or similar)
                    user = gd.get("user")
                    username = user if user and user != "-" else None

                    # If request URL contains username query (like ?user=admin), try parsing
                    uri = gd.get("uri", "")
                    if not username and "user=" in uri.lower():
                        user_match = re.search(r"user=([^&]+)", uri, re.IGNORECASE)
                        if user_match:
                            username = user_match.group(1)

                    return LogEntry(
                        timestamp=gd.get("time", ""),
                        source_ip=gd.get("ip"),
                        username=username,
                        method=gd.get("method"),
                        uri=uri,
                        status_code=int(gd.get("status", 0)),
                        response_size=resp_size,
                        user_agent=gd.get("ua"),
                        raw_line=line
                    )

            elif log_type == "apache_error":
                match = self.APACHE_ERROR_REGEX.match(line)
                if match:
                    gd = match.groupdict()
                    return LogEntry(
                        timestamp=gd.get("time", ""),
                        source_ip=gd.get("ip"),
                        uri=gd.get("message"),  # Store error text in URI for detection checks
                        raw_line=line
                    )

            elif log_type == "linux_auth":
                match = self.AUTH_LOG_REGEX.match(line)
                if match:
                    gd = match.groupdict()
                    msg = gd.get("message", "")
                    
                    # Extract source IP if present
                    ip_match = self.IP_EXTRACTOR.search(msg)
                    ip = ip_match.group(0) if ip_match else None

                    # Extract username
                    username = None
                    if "for invalid user" in msg:
                        user_match = re.search(r"for invalid user\s+(\S+)", msg)
                        if user_match:
                            username = user_match.group(1)
                    elif "for" in msg:
                        user_match = re.search(r"for\s+(\S+)", msg)
                        if user_match:
                            username = user_match.group(1)
                    elif "user=" in msg:
                        user_match = re.search(r"user=(\S+)", msg)
                        if user_match:
                            username = user_match.group(1)
                    elif gd.get("process") == "sudo":
                        # sudo:    aswin : TTY=pts/1 ...
                        user_match = re.match(r"\s*(\S+)\s*:", msg)
                        if user_match:
                            username = user_match.group(1)

                    return LogEntry(
                        timestamp=gd.get("time", ""),
                        source_ip=ip,
                        username=username,
                        raw_line=line
                    )

            elif log_type == "firewall_iptables":
                match = self.IPTABLES_REGEX.match(line)
                if match:
                    gd = match.groupdict()
                    port_str = gd.get("dpt", "")
                    dest_port = f":{port_str}" if port_str else ""
                    return LogEntry(
                        timestamp=gd.get("time", ""),
                        source_ip=gd.get("src_ip"),
                        uri=f"Blocked Packet PROTO={gd.get('proto')} DST={gd.get('dst_ip')}{dest_port}",
                        raw_line=line
                    )

            # Fallback "custom" parser for any text line
            # Scrapes timestamp and IP address to build normalized format
            ip_match = self.IP_EXTRACTOR.search(line)
            date_match = self.DATE_EXTRACTOR.search(line)

            ip = ip_match.group(0) if ip_match else None
            date_str = date_match.group(0) if date_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Basic username scraping if lines mention 'user', 'admin', 'login', etc.
            username = None
            user_match = re.search(r"(?i)user(?:name)?[:= ]+([^\s,;]+)", line)
            if user_match:
                username = user_match.group(1).strip("'\"")

            return LogEntry(
                timestamp=date_str,
                source_ip=ip,
                username=username,
                raw_line=line
            )

        except Exception as e:
            # Silently log parse failures of single lines in verbose logs to keep CLI clean
            log.debug(f"Line parsing error: {e}. Line: {line}")
            return None
        return None
