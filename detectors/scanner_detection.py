"""
LogGuardian AI Vulnerability Scanner & Reconnaissance Detector Module.
Detects sweeps on admin panels, backups, git repositories, and env files.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class ScannerDetector:
    """
    Analyzes log records to identify web vulnerability scanners and reconnaissance.
    """

    def __init__(self) -> None:
        self.detector_name = "scanner_detection"
        self.scanners_signatures = THREAT_SIGNATURES.get("scanners", [])
        self.sensitive_paths = THREAT_SIGNATURES.get("sensitive_paths", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Reconnaissance")
        self.technique_id = mitre.get("technique_id", "T1595")
        self.technique_name = mitre.get("technique_name", "Active Scanning")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for vulnerability assessment tools and path sweepings.
        
        Args:
            entries: List of normalized entries.
            
        Returns:
            A list of detected alerts.
        """
        alerts: List[Dict[str, Any]] = []

        for entry in entries:
            uri = entry.get("uri") or ""
            user_agent = entry.get("user_agent") or ""
            raw_line = entry.get("raw_line") or ""
            ip = entry.get("source_ip", "unknown")
            status_code = entry.get("status_code")

            # Check if User-Agent or URI contains scanner signatures
            matched = False
            matched_sig = ""
            reason = ""

            for sig in self.scanners_signatures:
                if re.search(sig, user_agent, re.IGNORECASE) or re.search(sig, uri, re.IGNORECASE):
                    matched = True
                    matched_sig = sig
                    reason = "User-Agent or request match for automated security scanner"
                    break

            if not matched:
                for path_sig in self.sensitive_paths:
                    if re.search(path_sig, uri, re.IGNORECASE):
                        matched = True
                        matched_sig = path_sig
                        reason = "Access attempt to sensitive system/configuration file path"
                        break

            if matched:
                # Severity check: if successful (HTTP 200/301/302), raise alert severity to HIGH
                # if 404 (Not Found) or 403 (Forbidden), keep at LOW/MEDIUM
                if status_code in [200, 301, 302]:
                    severity = "HIGH"
                    description = f"Vulnerability scanner or reconnaissance tool successfully matched target: {reason} on URI '{uri}' (HTTP: {status_code})."
                else:
                    severity = "MEDIUM"
                    description = f"Vulnerability scanner or reconnaissance sweep blocked/errored: {reason} on URI '{uri}'. Status: {status_code}."

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
                    "payload": f"Sign: '{matched_sig}' | Reason: {reason} (Line: '{raw_line}')"
                })

        return alerts
