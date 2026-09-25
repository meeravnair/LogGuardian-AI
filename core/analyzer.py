"""
LogGuardian AI Threat Analyzer Module.
Loads individual detector modules, executes them against parsed logs,
correlates alerts, and groups redundant triggers.
"""

from typing import List, Dict, Any
from detectors import (
    BruteForceDetector,
    SQLInjectionDetector,
    XSSDetector,
    DirectoryTraversalDetector,
    CommandInjectionDetector,
    FileInclusionDetector,
    ScannerDetector,
    UserAgentsDetector,
    DosDetector,
    AuthAnomalyDetector
)
from logger import log

class LogAnalyzer:
    """
    Main analysis engine that coordinates all detector algorithms,
    merges findings, and groups duplicates.
    """

    def __init__(self) -> None:
        # Instantiate all detector engines
        self.detectors = [
            BruteForceDetector(),
            SQLInjectionDetector(),
            XSSDetector(),
            DirectoryTraversalDetector(),
            CommandInjectionDetector(),
            FileInclusionDetector(),
            ScannerDetector(),
            UserAgentsDetector(),
            DosDetector(),
            AuthAnomalyDetector()
        ]
        log.info(f"Loaded {len(self.detectors)} threat detection engines.")

    def analyze_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs all threat detectors over the log entries.
        
        Args:
            entries: List of normalized entries (dicts).
            
        Returns:
            A list of raw, collected alerts.
        """
        raw_alerts: List[Dict[str, Any]] = []

        # Execute each detector
        for detector in self.detectors:
            try:
                log.info(f"Running detection engine: {detector.__class__.__name__}...")
                detections = detector.analyze(entries)
                if detections:
                    log.info(f"Engine {detector.__class__.__name__} flagged {len(detections)} threat indicators.")
                    raw_alerts.extend(detections)
            except Exception as e:
                log.error(f"Error executing detector {detector.__class__.__name__}: {e}")

        # Correlate and deduplicate alerts
        correlated_alerts = self._correlate_and_deduplicate(raw_alerts)
        log.info(f"Analysis completed. Merged {len(raw_alerts)} raw triggers into {len(correlated_alerts)} distinct alerts.")
        return correlated_alerts

    def _correlate_and_deduplicate(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups and deduplicates identical or closely recurring alerts.
        Identifies alert loops where the same IP hits the same detector with similar descriptions
        and aggregates them into single incidents with counters.
        
        Args:
            alerts: List of raw alerts.
            
        Returns:
            Deduplicated, correlated alerts list.
        """
        if not alerts:
            return []

        # Group by (source_ip, detector, severity, description)
        grouped_alerts: Dict[str, Dict[str, Any]] = {}

        for alert in alerts:
            ip = alert.get("source_ip", "unknown")
            det = alert.get("detector")
            sev = alert.get("severity")
            desc = alert.get("description")
            
            # Create a unique key for grouping
            group_key = f"{ip}_{det}_{sev}_{desc}"

            if group_key not in grouped_alerts:
                # Add count tracking metadata
                alert_copy = alert.copy()
                alert_copy["occured_count"] = 1
                alert_copy["timestamps"] = [alert.get("timestamp")]
                grouped_alerts[group_key] = alert_copy
            else:
                grouped_alerts[group_key]["occured_count"] += 1
                grouped_alerts[group_key]["timestamps"].append(alert.get("timestamp"))

        # Final pass to polish descriptions of grouped alerts
        deduplicated: List[Dict[str, Any]] = []
        for key, val in grouped_alerts.items():
            count = val["occured_count"]
            if count > 1:
                # Append count details to description
                val["description"] = f"{val['description']} (Triggered {count} times)"
            
            # Clean temporary list keys
            val.pop("timestamps", None)
            deduplicated.append(val)

        # Sort chronologically by timestamp
        try:
            from utils import parse_timestamp
            deduplicated.sort(key=lambda x: parse_timestamp(x.get("timestamp", "")))
        except Exception as e:
            log.warning(f"Failed to sort correlated alerts chronologically: {e}")

        return deduplicated
