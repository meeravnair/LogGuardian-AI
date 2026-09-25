"""
LogGuardian AI Local/Remote File Inclusion (LFI/RFI) Detector Module.
Detects inclusion wrappers and remote URI schema calls in requests.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class FileInclusionDetector:
    """
    Analyzes log records to identify File Inclusion exploits (LFI/RFI).
    """

    def __init__(self) -> None:
        self.detector_name = "file_inclusion"
        self.signatures = THREAT_SIGNATURES.get("file_inclusion", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Execution")
        self.technique_id = mitre.get("technique_id", "T1203")
        self.technique_name = mitre.get("technique_name", "Exploitation for Client Execution")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for file inclusion signatures.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []

        for entry in entries:
            uri = entry.get("uri") or ""
            raw_line = entry.get("raw_line") or ""

            # Exclude false positives for simple http/https requests inside web page paths if necessary,
            # but usually HTTP referer or remote URL in query params (e.g. ?page=http://malicious.site) is flagged.
            # RFI patterns are typical inside query strings: `?file=http...` or `?path=http...`
            # Let's check if the URI contains a query parameter that includes `http://` or `https://`
            if "?" in uri:
                query_parts = uri.split("?", 1)[1]
                for sig in self.signatures:
                    match = re.search(sig, query_parts, re.IGNORECASE)
                    if match:
                        matched_pattern = match.group(0)
                        ip = entry.get("source_ip", "unknown")
                        status_code = entry.get("status_code")
                        
                        if status_code == 200:
                            severity = "HIGH"
                            description = f"Successful File Inclusion (LFI/RFI) attempt from IP {ip} in query parameter '{uri}'."
                        else:
                            severity = "MEDIUM"
                            description = f"File Inclusion (LFI/RFI) attempt from IP {ip} in query parameter '{uri}'. Status: {status_code}."

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
