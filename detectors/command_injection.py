"""
LogGuardian AI Command Injection Detector Module.
Detects shell operators and command execution payloads in request lines.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class CommandInjectionDetector:
    """
    Analyzes log records to identify OS command execution attempts.
    """

    def __init__(self) -> None:
        self.detector_name = "command_injection"
        self.signatures = THREAT_SIGNATURES.get("command_injection", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Execution")
        self.technique_id = mitre.get("technique_id", "T1059")
        self.technique_name = mitre.get("technique_name", "Command and Scripting Interpreter")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scans normalized entries for command injection indicators.
        
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
                    
                    if status_code == 200:
                        severity = "CRITICAL"
                        description = f"Potential remote code execution (RCE) via Command Injection from IP {ip} targeting '{uri}' (HTTP 200)."
                    else:
                        severity = "HIGH"
                        description = f"Command Injection attempt blocked/errored from IP {ip} targeting '{uri}'. Status: {status_code}."

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
