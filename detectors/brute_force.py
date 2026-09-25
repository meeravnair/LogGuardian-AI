"""
LogGuardian AI Brute Force Detector Module.
Detects excessive authentication failures from a single source IP address
across SSH, Web auth, or Syslog events.
"""

from typing import List, Dict, Any
from datetime import datetime
from config import THRESHOLDS, MITRE_MAPPING
from utils import parse_timestamp

class BruteForceDetector:
    """
    Analyzes normalized logs to identify credential brute-forcing,
    including authentication spraying and dictionary attacks.
    """

    def __init__(self) -> None:
        self.detector_name = "brute_force"
        # Get threshold settings
        config_threshold = THRESHOLDS.get("brute_force", {})
        self.failures_threshold = config_threshold.get("failures_threshold", 5)
        self.window_seconds = config_threshold.get("window_seconds", 300)
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Credential Access")
        self.technique_id = mitre.get("technique_id", "T1110")
        self.technique_name = mitre.get("technique_name", "Brute Force")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs analysis on normalized log entries to detect brute force attacks.
        
        Args:
            entries: List of normalized log entries.
            
        Returns:
            A list of detected alert dictionaries.
        """
        alerts: List[Dict[str, Any]] = []
        
        # Group log lines by IP address with timestamps of failures
        # Supports Linux auth.log, SSH logs, and web server logs (HTTP 401 response codes)
        ip_failures: Dict[str, List[Dict[str, Any]]] = {}

        for entry in entries:
            ip = entry.get("source_ip")
            if not ip:
                continue

            is_failure = False
            username = entry.get("username")
            raw_line = entry.get("raw_line", "")

            # 1. Check for Linux/SSH auth failures
            if "fail" in raw_line.lower() or "invalid user" in raw_line.lower():
                is_failure = True
            
            # 2. Check for Web auth failures (HTTP status 401 Unauthorized)
            elif entry.get("status_code") == 401:
                is_failure = True
                
            # 3. Check for specific POST requests to login paths
            elif entry.get("method") == "POST" and any(path in entry.get("uri", "").lower() for path in ["login", "signin", "auth", "wp-login"]):
                # Web server logs might not show 401 for bad logins, but high density of POSTs is suspicious
                is_failure = True

            if is_failure:
                if ip not in ip_failures:
                    ip_failures[ip] = []
                ip_failures[ip].append(entry)

        # Apply sliding window threshold for each IP
        for ip, failures in ip_failures.items():
            if len(failures) < self.failures_threshold:
                continue

            # Sort failures by timestamp
            sorted_failures = sorted(failures, key=lambda x: parse_timestamp(x.get("timestamp", "")))

            for i in range(len(sorted_failures)):
                # Take current failure and see how many failures occurred in the next `window_seconds`
                current_time = parse_timestamp(sorted_failures[i].get("timestamp", ""))
                window_failures = [sorted_failures[i]]
                
                for j in range(i + 1, len(sorted_failures)):
                    compare_time = parse_timestamp(sorted_failures[j].get("timestamp", ""))
                    diff = (compare_time - current_time).total_seconds()
                    
                    if 0 <= diff <= self.window_seconds:
                        window_failures.append(sorted_failures[j])
                    else:
                        break

                if len(window_failures) >= self.failures_threshold:
                    # Gather metadata
                    usernames = list(set([x.get("username") for x in window_failures if x.get("username")]))
                    user_str = ", ".join(usernames) if usernames else "unknown user(s)"
                    last_failure = window_failures[-1]
                    
                    # Determine severity based on attempt volume
                    severity = "MEDIUM"
                    if len(window_failures) >= 15:
                        severity = "HIGH"
                    if len(window_failures) >= 50:
                        severity = "CRITICAL"

                    alerts.append({
                        "timestamp": last_failure.get("timestamp"),
                        "source_ip": ip,
                        "username": usernames[0] if usernames else None,
                        "detector": self.detector_name,
                        "severity": severity,
                        "description": f"Brute force attempt detected from IP {ip}. "
                                       f"Encountered {len(window_failures)} authentication failures targeting: {user_str}.",
                        "tactic": self.tactic,
                        "technique_id": self.technique_id,
                        "technique_name": self.technique_name,
                        "payload": f"First Failure: '{window_failures[0].get('raw_line')}' | Last Failure: '{last_failure.get('raw_line')}'"
                    })
                    # Skip past these failures to avoid duplicate overlapping alerts
                    i += len(window_failures) - 1

        return alerts
