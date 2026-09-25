"""
LogGuardian AI User Agent Anomaly Detector Module.
Identifies suspicious, missing, empty, or bot-like User-Agents in web requests.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class UserAgentsDetector:
    """
    Analyzes request user agents to identify automated scripting engines and bots.
    """

    def __init__(self) -> None:
        self.detector_name = "user_agents"
        self.signatures = THREAT_SIGNATURES.get("suspicious_user_agents", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Defense Evasion")
        self.technique_id = mitre.get("technique_id", "T1036")
        self.technique_name = mitre.get("technique_name", "Masquerading")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for suspicious user agents.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []

        for entry in entries:
            # Only run on web logs which have User-Agents
            if entry.get("user_agent") is None:
                continue
                
            ua = entry.get("user_agent", "").strip()
            ip = entry.get("source_ip", "unknown")
            raw_line = entry.get("raw_line", "")

            # 1. Missing or Empty User-Agent
            if not ua or ua == "-" or ua == '""':
                alerts.append({
                    "timestamp": entry.get("timestamp"),
                    "source_ip": ip,
                    "username": entry.get("username"),
                    "detector": self.detector_name,
                    "severity": "LOW",
                    "description": f"Missing or empty User-Agent header from IP {ip}.",
                    "tactic": self.tactic,
                    "technique_id": self.technique_id,
                    "technique_name": self.technique_name,
                    "payload": f"Raw log line: '{raw_line}'"
                })
                continue

            # 2. Blocklisted User-Agent check
            for sig in self.signatures:
                if re.search(sig, ua, re.IGNORECASE):
                    alerts.append({
                        "timestamp": entry.get("timestamp"),
                        "source_ip": ip,
                        "username": entry.get("username"),
                        "detector": self.detector_name,
                        "severity": "LOW",
                        "description": f"Suspicious or automated scripting User-Agent '{ua}' from IP {ip}.",
                        "tactic": self.tactic,
                        "technique_id": self.technique_id,
                        "technique_name": self.technique_name,
                        "payload": f"Matched signature '{sig}' in User-Agent header. (Line: '{raw_line}')"
                    })
                    break

        return alerts
