"""
LogGuardian AI Denial of Service (DoS) Detector Module.
Identifies high density of requests from a single IP source within a time window.
"""

from typing import List, Dict, Any
from datetime import datetime
from config import THRESHOLDS, MITRE_MAPPING
from utils import parse_timestamp

class DosDetector:
    """
    Analyzes request frequency to identify Denial of Service (DoS) activity.
    """

    def __init__(self) -> None:
        self.detector_name = "dos_detector"
        config_threshold = THRESHOLDS.get("dos", {})
        self.requests_threshold = config_threshold.get("requests_threshold", 100)
        self.window_seconds = config_threshold.get("window_seconds", 60)
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Impact")
        self.technique_id = mitre.get("technique_id", "T1498")
        self.technique_name = mitre.get("technique_name", "Network Denial of Service")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for high request density.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []
        
        # Group log lines by IP address with timestamps
        ip_requests: Dict[str, List[Dict[str, Any]]] = {}

        for entry in entries:
            # We only track IPs in web/access logs or firewalls
            ip = entry.get("source_ip")
            if not ip:
                continue

            if ip not in ip_requests:
                ip_requests[ip] = []
            ip_requests[ip].append(entry)

        # Apply sliding window threshold for each IP
        for ip, reqs in ip_requests.items():
            if len(reqs) < self.requests_threshold:
                continue

            # Sort requests by timestamp
            sorted_reqs = sorted(reqs, key=lambda x: parse_timestamp(x.get("timestamp", "")))

            for i in range(len(sorted_reqs)):
                current_time = parse_timestamp(sorted_reqs[i].get("timestamp", ""))
                window_reqs = [sorted_reqs[i]]
                
                for j in range(i + 1, len(sorted_reqs)):
                    compare_time = parse_timestamp(sorted_reqs[j].get("timestamp", ""))
                    diff = (compare_time - current_time).total_seconds()
                    
                    if 0 <= diff <= self.window_seconds:
                        window_reqs.append(sorted_reqs[j])
                    else:
                        break

                if len(window_reqs) >= self.requests_threshold:
                    last_req = window_reqs[-1]
                    
                    # Severity escalations
                    severity = "MEDIUM"
                    if len(window_reqs) >= 500:
                        severity = "HIGH"
                    if len(window_reqs) >= 2000:
                        severity = "CRITICAL"

                    alerts.append({
                        "timestamp": last_req.get("timestamp"),
                        "source_ip": ip,
                        "username": last_req.get("username"),
                        "detector": self.detector_name,
                        "severity": severity,
                        "description": f"Potential Denial of Service (DoS) attack from IP {ip}. "
                                       f"Encountered {len(window_reqs)} requests within a {self.window_seconds}-second window.",
                        "tactic": self.tactic,
                        "technique_id": self.technique_id,
                        "technique_name": self.technique_name,
                        "payload": f"First Request: '{window_reqs[0].get('uri')}' | Last Request: '{last_req.get('uri')}' | Total Volumetric Hits: {len(window_reqs)}"
                    })
                    # Skip past this window to avoid overlapping alerts
                    i += len(window_reqs) - 1

        return alerts
