"""
LogGuardian AI Utilities Module.
Contains date parsing, IP geolocator simulations, formatting utility functions,
and threat metadata resolvers.
"""

import re
import html
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from dateutil import parser as date_parser
from logger import log

# Simulated GeoIP lookup database based on hash values for consistency
COUNTRIES = [
    {"name": "United States", "code": "US", "isp": "Amazon Technologies Inc."},
    {"name": "Germany", "code": "DE", "isp": "Hetzner Online GmbH"},
    {"name": "China", "code": "CN", "isp": "Chinanet"},
    {"name": "Russia", "code": "RU", "isp": "Rostelecom OJSC"},
    {"name": "Netherlands", "code": "NL", "isp": "LeaseWeb B.V."},
    {"name": "United Kingdom", "code": "GB", "isp": "British Telecommunications"},
    {"name": "India", "code": "IN", "isp": "Reliance Jio Infocomm"},
    {"name": "Brazil", "code": "BR", "isp": "Claro Brasil"},
    {"name": "Ukraine", "code": "UA", "isp": "Kyivstar PJSC"},
    {"name": "France", "code": "FR", "isp": "OVH SAS"}
]

def parse_timestamp(ts_str: str) -> datetime:
    """
    Parses a variety of log timestamp strings into standard Python datetime objects.
    
    Supported formats include:
      - Apache/Nginx format: "17/May/2026:10:05:03 +0000"
      - Linux auth.log/Syslog: "May 17 10:05:03" or "2026-05-17T10:05:03.123456+00:00"
      - Epoch timestamp
    
    Args:
        ts_str: The timestamp string to parse.
        
    Returns:
        A datetime object. If parsing fails, returns current datetime.
    """
    if not ts_str:
        return datetime.now()
        
    # Clean the string (e.g., strip square brackets commonly surrounding log dates)
    cleaned = ts_str.strip("[]() ")

    # Try Apache format first: "17/May/2026:10:05:03 +0000"
    try:
        # Some apache timestamps have semicolons instead of colons separating time
        apache_match = re.match(r"(\d{2}/\w{3}/\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})", cleaned)
        if apache_match:
            date_part, h, m, s, tz = apache_match.groups()
            cleaned_ap = f"{date_part} {h}:{m}:{s} {tz}"
            return datetime.strptime(cleaned_ap, "%d/%b/%Y %H:%M:%S %z")
    except Exception as e:
        log.debug(f"Failed Apache format parse for '{ts_str}': {e}")

    # Try general date util parser
    try:
        dt = date_parser.parse(cleaned)
        # If no year is specified (common in auth.log), default to current year
        if dt.year == 1900 or not re.search(r"\b\d{4}\b", cleaned):
            dt = dt.replace(year=datetime.now().year)
        return dt
    except Exception as e:
        log.warning(f"Could not parse timestamp '{ts_str}', defaulting to current time. Error: {e}")
        return datetime.now()

def get_ip_geo(ip: str) -> Dict[str, str]:
    """
    Simulates a GeoIP lookup using the IP's MD5 hash to produce consistent,
    realistic country and ISP details. Used to populate the dashboard UI.
    
    Args:
        ip: Target IP address.
        
    Returns:
        A dictionary containing country, country_code, and isp.
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return {"country": "Local Loopback", "code": "LOCAL", "isp": "Internal Network"}

    # Handle private IP ranges
    private_ip_patterns = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\."
    ]
    for pattern in private_ip_patterns:
        if re.match(pattern, ip):
            return {"country": "Private Network", "code": "PVT", "isp": "RFC 1918 Address Space"}

    # Hash the IP address to pick a deterministic country and ISP index
    hash_val = int(hashlib.md5(ip.encode("utf-8")).hexdigest(), 16)
    geo_idx = hash_val % len(COUNTRIES)
    geo = COUNTRIES[geo_idx]

    return {
        "country": geo["name"],
        "code": geo["code"],
        "isp": geo["isp"]
    }

def format_bytes(size_bytes: int) -> str:
    """
    Formats a byte size into human-readable bytes/KB/MB/GB.
    
    Args:
        size_bytes: Number of bytes.
        
    Returns:
        Formatted size string.
    """
    if size_bytes == 0:
        return "0 B"
    
    size_name = ("B", "KB", "MB", "GB", "TB")
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def sanitize_html(input_str: str) -> str:
    """
    Escapes HTML entities to prevent Cross-Site Scripting when rendering payloads.
    
    Args:
        input_str: Raw string to sanitize.
        
    Returns:
        Sanitized string.
    """
    if not input_str:
        return ""
    return html.escape(input_str)

def get_threat_label(detector: str) -> str:
    """
    Returns a clean, readable name for a detector type.
    
    Args:
        detector: Name of the detector.
        
    Returns:
        Readable label.
    """
    labels = {
        "brute_force": "Brute Force Attack",
        "sql_injection": "SQL Injection (SQLi)",
        "xss": "Cross-Site Scripting (XSS)",
        "directory_traversal": "Directory Traversal",
        "command_injection": "OS Command Injection",
        "file_inclusion": "Local/Remote File Inclusion",
        "scanner_detection": "Vulnerability Reconnaissance",
        "user_agents": "Malicious User Agent",
        "dos_detector": "Denial of Service (DoS)",
        "auth_anomaly": "Authentication Anomaly"
    }
    return labels.get(detector, detector.replace("_", " ").title())
