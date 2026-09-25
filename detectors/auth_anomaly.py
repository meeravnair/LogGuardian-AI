"""
LogGuardian AI Authentication Anomaly Detector Module.
Identifies suspicious login sequences, direct root logins, and abnormal sudo usage.
"""

from typing import List, Dict, Any
from datetime import datetime
from config import THRESHOLDS, MITRE_MAPPING
from utils import parse_timestamp

class AuthAnomalyDetector:
    """
    Analyzes authentication logs to find logical anomalies in login activity.
    """

    def __init__(self) -> None:
        self.detector_name = "auth_anomaly"
        config_threshold = THRESHOLDS.get("auth_anomaly", {})
        self.success_window = config_threshold.get("success_after_failure_window", 600)
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Lateral Movement")
        self.technique_id = mitre.get("technique_id", "T1021")
        self.technique_name = mitre.get("technique_name", "Remote Services")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for authentication logical flows.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []
        
        # 1. Group login successes and failures per IP/username to check for successful login after failures
        user_events: Dict[str, List[Dict[str, Any]]] = {}

        for entry in entries:
            raw_line = entry.get("raw_line", "").lower()
            ip = entry.get("source_ip")
            username = entry.get("username")
            
            if not username:
                continue

            # Identify if it is a login event (SSH or Web)
            is_success = False
            is_failure = False

            if "accepted" in raw_line or "session opened" in raw_line or (entry.get("method") == "POST" and entry.get("status_code") == 200 and any(p in entry.get("uri", "").lower() for p in ["login", "signin"])):
                is_success = True
            elif "fail" in raw_line or "invalid user" in raw_line or entry.get("status_code") == 401:
                is_failure = True

            if is_success or is_failure:
                key = f"{ip}_{username}" if ip else username
                if key not in user_events:
                    user_events[key] = []
                
                entry_copy = entry.copy()
                entry_copy["is_success"] = is_success
                entry_copy["is_failure"] = is_failure
                user_events[key].append(entry_copy)

            # 2. Check for Sudo anomalies or direct Root logins
            if "accepted" in raw_line and username == "root" and ip and ip != "127.0.0.1":
                # Direct external root login
                alerts.append({
                    "timestamp": entry.get("timestamp"),
                    "source_ip": ip,
                    "username": "root",
                    "detector": self.detector_name,
                    "severity": "HIGH",
                    "description": f"Direct remote root logon session established from IP {ip}.",
                    "tactic": self.tactic,
                    "technique_id": self.technique_id,
                    "technique_name": self.technique_name,
                    "payload": f"Log Line: '{entry.get('raw_line')}'"
                })

            if "sudo:" in raw_line and "command=" in raw_line:
                # Sudo execution trace
                severity = "LOW"
                desc = f"Administrative command execution (sudo) by user '{username}'."
                if "root" in raw_line or "rm -rf" in raw_line or "chmod" in raw_line:
                    severity = "MEDIUM"
                    desc = f"Suspicious administrative command execution (sudo) by user '{username}'."
                
                alerts.append({
                    "timestamp": entry.get("timestamp"),
                    "source_ip": ip,
                    "username": username,
                    "detector": self.detector_name,
                    "severity": severity,
                    "description": desc,
                    "tactic": self.tactic,
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudoers",
                    "payload": f"Log Line: '{entry.get('raw_line')}'"
                })

        # Process grouped user events for "success after failure" anomalies
        for key, events in user_events.items():
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda x: parse_timestamp(x.get("timestamp", "")))
            
            failures_count = 0
            first_failure_time = None
            
            for ev in sorted_events:
                if ev["is_failure"]:
                    if failures_count == 0:
                        first_failure_time = parse_timestamp(ev.get("timestamp", ""))
                    failures_count += 1
                elif ev["is_success"]:
                    if failures_count >= 3 and first_failure_time:
                        success_time = parse_timestamp(ev.get("timestamp", ""))
                        diff = (success_time - first_failure_time).total_seconds()
                        
                        if diff <= self.success_window:
                            ip_part = ev.get("source_ip", "unknown")
                            user_part = ev.get("username", "unknown")
                            alerts.append({
                                "timestamp": ev.get("timestamp"),
                                "source_ip": ip_part,
                                "username": user_part,
                                "detector": self.detector_name,
                                "severity": "CRITICAL",
                                "description": f"Critical Auth Anomaly: Successful login for '{user_part}' from IP {ip_part} after {failures_count} authentication failures within 10 minutes (Potential compromised account/successful brute-force).",
                                "tactic": self.tactic,
                                "technique_id": "T1110.001",
                                "technique_name": "Brute Force: Password Guessing",
                                "payload": f"Success line: '{ev.get('raw_line')}' | Total failures prior: {failures_count}"
                            })
                    # Reset failure tracking after any login success
                    failures_count = 0
                    first_failure_time = None

        return alerts
