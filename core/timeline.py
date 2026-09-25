"""
LogGuardian AI Timeline Module.
Sorts and structures events chronologically, identifying the progression
of attack stages (Reconnaissance -> Access -> Execution -> Impact).
"""

from typing import List, Dict, Any
from utils import parse_timestamp

class TimelineGenerator:
    """
    Constructs a chronological attack narrative by correlating different alerts
    and mapping them to standard intrusion lifecycle phases.
    """

    # Stage mapping based on MITRE Tactics
    STAGE_ORDER = {
        "Reconnaissance": 1,
        "Resource Development": 2,
        "Initial Access": 3,
        "Execution": 4,
        "Persistence": 5,
        "Privilege Escalation": 6,
        "Defense Evasion": 7,
        "Credential Access": 8,
        "Discovery": 9,
        "Lateral Movement": 10,
        "Collection": 11,
        "Command and Control": 12,
        "Exfiltration": 13,
        "Impact": 14
    }

    def generate_timeline(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts alerts chronologically and enriches them with stage-progression indicators.
        
        Args:
            alerts: List of deduplicated alerts.
            
        Returns:
            A chronologically sorted list of alerts, enriched with lifecycle details.
        """
        if not alerts:
            return []

        # Sort based on timestamp
        sorted_alerts = sorted(alerts, key=lambda x: parse_timestamp(x.get("timestamp", "")))

        timeline: List[Dict[str, Any]] = []
        start_time = parse_timestamp(sorted_alerts[0].get("timestamp", ""))

        for alert in sorted_alerts:
            tactic = alert.get("tactic", "Discovery")
            stage_num = self.STAGE_ORDER.get(tactic, 9) # Default to Discovery stage

            alert_time = parse_timestamp(alert.get("timestamp", ""))
            time_delta_sec = int((alert_time - start_time).total_seconds())

            # Convert time delta into a nice readable format (e.g. +10s, +5m 12s)
            if time_delta_sec == 0:
                time_offset = "T-00:00"
            else:
                m, s = divmod(abs(time_delta_sec), 60)
                h, m = divmod(m, 60)
                sign = "+" if time_delta_sec >= 0 else "-"
                if h > 0:
                    time_offset = f"{sign}{h:02d}h:{m:02d}m:{s:02d}s"
                else:
                    time_offset = f"{sign}{m:02d}m:{s:02d}s"

            timeline.append({
                "timestamp": alert.get("timestamp"),
                "time_offset": time_offset,
                "source_ip": alert.get("source_ip"),
                "detector": alert.get("detector"),
                "severity": alert.get("severity"),
                "description": alert.get("description"),
                "tactic": tactic,
                "technique_id": alert.get("technique_id"),
                "technique_name": alert.get("technique_name"),
                "stage_index": stage_num,
                "payload": alert.get("payload")
            })

        return timeline
