"""
LogGuardian AI Risk Engine Module.
Calculates individual alert severity weights, overall system security score (0-100),
and resolves the descriptive risk rating.
"""

from typing import List, Dict, Any, Tuple
from config import SEVERITY_POINTS
from logger import log

class RiskEngine:
    """
    Computes system-level threat metrics and security ratings based on
    incident severity levels and volume of alerts.
    """

    @staticmethod
    def calculate_score(alerts: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Calculates the system security score (0-100) and mapping risk rating.
        
        Score deduction weights:
          - CRITICAL: 12 points
          - HIGH: 8 points
          - MEDIUM: 5 points
          - LOW: 2 points
          - INFO: 0 points
        
        Args:
            alerts: List of correlated alert objects.
            
        Returns:
            A tuple of (security_score, risk_rating).
        """
        base_score = 100
        total_deduction = 0

        for alert in alerts:
            severity = alert.get("severity", "MEDIUM").upper()
            weight = SEVERITY_POINTS.get(severity, 5)
            
            # Account for deduplicated occurrences count
            count = alert.get("occured_count", 1)
            
            # Apply a logarithmic scaling to occurrences of the same alert to avoid
            # dropping the score to 0 due to a single repeating log entry (e.g. DoS scan)
            # Deduction = weight * log2(count + 1) or simple cap
            import math
            occurrences_multiplier = 1.0 + math.log2(count)
            
            total_deduction += weight * occurrences_multiplier

        # Cast to integer and cap
        security_score = max(0, min(100, int(base_score - total_deduction)))

        # Assign risk rating
        if security_score == 100:
            risk_rating = "SECURE"
        elif security_score >= 85:
            risk_rating = "LOW"
        elif security_score >= 60:
            risk_rating = "MEDIUM"
        elif security_score >= 35:
            risk_rating = "HIGH"
        else:
            risk_rating = "CRITICAL"

        log.info(f"Risk calculation: Total deductions = {total_deduction:.2f}. "
                 f"Final Security Score = {security_score} ({risk_rating}).")

        return security_score, risk_rating
