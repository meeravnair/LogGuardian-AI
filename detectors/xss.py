"""
LogGuardian AI Cross-Site Scripting (XSS) Detector Module.
Detects markup and script execution payloads in web request streams.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class XSSDetector:
    """
    Analyzes log records to identify client-side script injection attacks.
    """

    def __init__(self) -> None:
        self.detector_name = "xss"
        self.signatures = THREAT_SIGNATURES.get("xss", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Initial Access")
        self.technique_id = mitre.get("technique_id", "T1190")
        self.technique_name = mitre.get("technique_name", "Exploit Public-Facing Application")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for script tags and attributes.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []

        for entry in entries:
            uri = entry.get("uri") or ""
            raw_line = entry.get("raw_line") or ""

            # Check signatures against URI
            for sig in self.signatures:
                match = re.search(sig, uri, re.IGNORECASE)
                if match:
                    matched_pattern = match.group(0)
                    ip = entry.get("source_ip", "unknown")
                    status_code = entry.get("status_code")
                    
                    if status_code == 200:
                        severity = "HIGH"
                        description = f"Cross-Site Scripting (XSS) payload detected from IP {ip} in URI '{uri}' with response code 200."
                    else:
                        severity = "MEDIUM"
                        description = f"Cross-Site Scripting (XSS) payload detected from IP {ip} in URI '{uri}'. Response status: {status_code}."

                    alerts.append({
                        "timestamp": entry.get("timestamp"),
                        "source_ip": ip,
                        "username": entry.get("username"),
                        "detector": self.detector_name,
                        "severity": severity,
                        "description": description,
                        "tactic": self.tactic,
                        "technique_id": self.technique_id,
                        "technique_name": self.technique_name,
                        "payload": f"Matched signature '{sig}' in segment: '{matched_pattern}' (Line: '{raw_line}')"
                    })
                    break

        return alerts
