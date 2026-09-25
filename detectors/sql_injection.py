"""
LogGuardian AI SQL Injection (SQLi) Detector Module.
Inspects request URI, parameters, and payloads for SQL Injection signatures.
"""

import re
from typing import List, Dict, Any
from config import THREAT_SIGNATURES, MITRE_MAPPING

class SQLInjectionDetector:
    """
    Analyzes log fields (URI, query, headers) for traces of SQL query manipulation.
    """

    def __init__(self) -> None:
        self.detector_name = "sql_injection"
        self.signatures = THREAT_SIGNATURES.get("sql_injection", [])
        
        # MITRE maps
        mitre = MITRE_MAPPING.get(self.detector_name, {})
        self.tactic = mitre.get("tactic", "Initial Access")
        self.technique_id = mitre.get("technique_id", "T1190")
        self.technique_name = mitre.get("technique_name", "Exploit Public-Facing Application")

    def analyze(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs SQL injection signature checks.
        
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

            # Combine fields to inspect
            inspect_text = f"{uri} {user_agent}"
            
            # Check signatures
            for sig in self.signatures:
                match = re.search(sig, inspect_text, re.IGNORECASE)
                if match:
                    matched_pattern = match.group(0)
                    ip = entry.get("source_ip", "unknown")
                    
                    # Compute severity: if status is 200 (Success) it could mean successful exploit (HIGH)
                    # if status is 4xx or 5xx, it was likely blocked or errored (MEDIUM)
                    status_code = entry.get("status_code")
                    if status_code == 200:
                        severity = "HIGH"
                        description = f"SQL Injection attempt from IP {ip} on URI '{uri}'. HTTP Status 200 indicates potential exploit success."
                    else:
                        severity = "MEDIUM"
                        description = f"SQL Injection attempt blocked/errored from IP {ip} on URI '{uri}'. HTTP Status: {status_code}."

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
                        "payload": f"Matched signature '{sig}' in string snippet: '{matched_pattern}' (Line: '{raw_line}')"
                    })
                    # Found a match on this entry, break signature loop to avoid multi-alerts on same line
                    break

        return alerts
