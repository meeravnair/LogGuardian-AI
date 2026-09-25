"""
LogGuardian AI Directory Traversal Detector Module.
Detects escape sequences and references to sensitive system files.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class DirectoryTraversalDetector:
    """
    Analyzes log records to identify path traversal and directory escape attempts.
    """

    def __init__(self) -> None:
        self.detector_name = "directory_traversal"
        self.signatures = THREAT_SIGNATURES.get("directory_traversal", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Credential Access")
        self.technique_id = mitre.get("technique_id", "T1552")
        self.technique_name = mitre.get("technique_name", "Unsecured Credentials")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for directory traversal payloads.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []

        for entry in entries:
            uri = entry.get("uri") or ""
            raw_line = entry.get("raw_line") or ""

            # Check signatures
            for sig in self.signatures:
                match = re.search(sig, uri, re.IGNORECASE)
                if match:
                    matched_pattern = match.group(0)
                    ip = entry.get("source_ip", "unknown")
                    status_code = entry.get("status_code")
                    
                    # If traversal accessed a sensitive file like passwd and status was 200, raise severity
                    if status_code == 200:
                        severity = "HIGH"
                        description = f"Successful Directory Traversal attempt from IP {ip} targeting '{uri}' (HTTP 200)."
                    else:
                        severity = "MEDIUM"
                        description = f"Directory Traversal attempt blocked/errored from IP {ip} targeting '{uri}'. Status: {status_code}."

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
