"""
LogGuardian AI AI-Assisted Security Summary Module.
Generates analyst-grade executive threat briefs, root cause analysis,
and defense hardening recommendations. Supports rule-based local expert modes
and optional API-based LLM summary generation.
"""

import os
import requests
from typing import List, Dict, Any
from logger import log
from utils import get_threat_label

class AISummaryGenerator:
    """
    Simulates a junior SOC analyst, writing up a structured security
    investigation summary based on the scan results.
    """

    def __init__(self) -> None:
        self.openai_key = os.environ.get("OPENAI_API_KEY")
        self.gemini_key = os.environ.get("GEMINI_API_KEY")

    def generate_summary(self,
                         filename: str,
                         log_type: str,
                         security_score: int,
                         risk_rating: str,
                         alerts: List[Dict[str, Any]]) -> str:
        """
        Generates a professional markdown-formatted investigation summary.
        If API keys are configured, it queries the LLM; otherwise, it falls back
        to a highly detailed rule-based expert parser.
        
        Args:
            filename: Log file scanned.
            log_type: Normalized log format.
            security_score: 0-100 score.
            risk_rating: Low/Medium/High/Critical.
            alerts: List of detected alerts.
            
        Returns:
            A markdown string containing the security investigation write-up.
        """
        if not alerts:
            return self._generate_clean_summary(filename, log_type)

        if self.gemini_key:
            return self._query_gemini(filename, log_type, security_score, risk_rating, alerts)
        elif self.openai_key:
            return self._query_openai(filename, log_type, security_score, risk_rating, alerts)
            
        return self._generate_local_expert_summary(filename, log_type, security_score, risk_rating, alerts)

    def _generate_clean_summary(self, filename: str, log_type: str) -> str:
        """Generates writeup for logs with no alerts."""
        return f"""### 🛡️ Executive Incident Summary
**Status**: SECURE (No Threats Identified)  
**Target Resource**: `{filename}` ({log_type})  
**Analyst Note**: Investigation completed. No anomalous patterns, known threat signatures, login failures, or web attack payloads were detected in the log stream.

---

### 🔍 Analysis Details
- No indicators of compromise (IOCs) matching SQLi, XSS, Path Traversal, Command Injection, or automated reconnaissance sweeps were found.
- Authentication operations within the log appear normal.

---

### 💡 Recommendations
- **Continuous Monitoring**: Maintain centralized logging and review schedules.
- **Regular Backups**: Ensure offsite backups are active and verified.
"""

    def _generate_local_expert_summary(self,
                                       filename: str,
                                       log_type: str,
                                       security_score: int,
                                       risk_rating: str,
                                       alerts: List[Dict[str, Any]]) -> str:
        """Rule-based local expert system to draft highly professional SOC writeups."""
        
        # Analyze alert statistics
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        detectors = {}
        ips = set()
        users = set()
        mitre_techniques = set()

        for a in alerts:
            sev = a.get("severity", "MEDIUM").upper()
            severities[sev] = severities.get(sev, 0) + 1
            
            det = a.get("detector")
            detectors[det] = detectors.get(det, 0) + 1
            
            if a.get("source_ip"):
                ips.add(a.get("source_ip"))
            if a.get("username"):
                users.add(a.get("username"))
                
            tech_id = a.get("technique_id")
            tech_name = a.get("technique_name")
            if tech_id and tech_name:
                mitre_techniques.add(f"{tech_name} ({tech_id})")

        # Compile lists
        detected_attacks_str = ", ".join([f"**{get_threat_label(k)}** ({v} hits)" for k, v in detectors.items()])
        mitre_list_str = "\n".join([f"- {tech}" for tech in mitre_techniques])
        ip_list_str = ", ".join([f"`{ip}`" for ip in list(ips)[:5]])
        user_list_str = ", ".join([f"`{u}`" for u in list(users)[:5]]) if users else "None identified"

        # Threat Assessment Summary Text
        threat_level_desc = ""
        if risk_rating == "CRITICAL":
            threat_level_desc = "The system is under active compromise or has sustained severe exploitation attempts. Immediate incident response actions are required."
        elif risk_rating == "HIGH":
            threat_level_desc = "Significant hostile activity has been logged. Serious threat indicators suggest targeted attacks or scanning loops that require prompt attention."
        elif risk_rating == "MEDIUM":
            threat_level_desc = "Moderate security events detected. Vulnerability scans or unauthorized access attempts were identified but may have been blocked."
        else:
            threat_level_desc = "Minor anomalous alerts detected. Mostly low-priority scraping or automated client warnings."

        # Actionable recommendations based on detectors
        containment_steps = []
        if "brute_force" in detectors or "auth_anomaly" in detectors:
            containment_steps.append("- **Account Lockout & Credentials**: Enable lockout policies. Enforce password rotations for targeted accounts. Verify if SSH root logons are disabled (`PermitRootLogin no` in sshd_config).")
            containment_steps.append("- **IP Blocking**: Temporarily or permanently null-route/block the source IPs (" + ip_list_str + ") at the network edge or host firewall (e.g., `iptables` / `fail2ban`).")
        if "sql_injection" in detectors or "xss" in detectors or "directory_traversal" in detectors or "command_injection" in detectors:
            containment_steps.append("- **Web Application Firewall (WAF)**: Deploy ModSecurity or cloud-native WAF rules targeting SQLi, XSS, and LFI patterns to inspect and filter inbound payloads.")
            containment_steps.append("- **Code Hardening**: Implement parameterized queries for database interactions and sanitize/encode output fields to neutralize XSS payloads.")
        if "dos_detector" in detectors:
            containment_steps.append("- **Rate Limiting**: Configure request rate limits at the web server (Nginx rate-limiting) or CDN (Cloudflare) levels to mitigate volume floods.")
        if "scanner_detection" in detectors:
            containment_steps.append("- **Reconnaissance Countermeasures**: Block IPs executing automated scans. Disable directory listings and return generic error pages (404/403) to scan sweeps.")

        containment_actions_markdown = "\n".join(containment_steps) if containment_steps else "- **Continuous Auditing**: No urgent actions required. Keep scanning log profiles."

        # Compile complete report markdown
        report_md = f"""### 🛡️ Executive Incident Summary
**Status**: Incident Flagged (Risk Level: **{risk_rating}** | Security Health Score: **{security_score}/100**)  
**Scanned Log**: `{filename}` (Format: `{log_type}`)  
**Impact Assessment**: {threat_level_desc}  

---

### 🔍 Threat Analysis & Findings
During the log correlation cycle, LogGuardian AI identified the following threat vectors:
- **Detections**: {detected_attacks_str}  
- **Top Adversary IPs**: {ip_list_str}  
- **Targeted Accounts**: {user_list_str}  

#### 🎯 MITRE ATT&CK Techniques Mapped:
{mitre_list_str}

#### 📋 Alert Severity Breakdown:
- **Critical Alerts**: {severities['CRITICAL']}
- **High Alerts**: {severities['HIGH']}
- **Medium Alerts**: {severities['MEDIUM']}
- **Low/Info Alerts**: {severities['LOW'] + severities['INFO']}

---

### 🚨 Containment Actions (Immediate Playbook)
Based on the identified attack vectors, the following operations are recommended to isolate and contain the threat:
{containment_actions_markdown}

---

### 🛠️ Long-Term Remediation & System Hardening
1. **Network Segregation**: Restrict access to administrative interfaces (such as SSH, SSH Admin panels) using access control lists (ACLs) or a trusted VPN (Virtual Private Network).
2. **Log Consolidation**: Implement a centralized SIEM/Syslog server (Elasticsearch, Graylog) to stream logs in real-time, preventing logs manipulation by attackers.
3. **Patch Management**: Ensure the host operating system, web servers, and application libraries are patched against CVEs referenced by path traversal and execution payloads.
4. **Multi-Factor Authentication (MFA)**: Enforce MFA for all external-facing authentication interfaces to neutralize credential stuffing.
"""
        return report_md

    def _query_openai(self, filename: str, log_type: str, score: int, rating: str, alerts: List[Dict[str, Any]]) -> str:
        """Queries OpenAI API to generate the investigation summary."""
        try:
            url = "https://api.openai.com/v1/chat/completypes"
            headers = {
                "Authorization": f"Bearer {self.openai_key}",
                "Content-Type": "application/json"
            }
            
            # Format alerts payload to limit tokens
            summary_alerts = []
            for a in alerts[:30]:  # Limit to top 30 alerts to save token space
                summary_alerts.append({
                    "timestamp": a.get("timestamp"),
                    "ip": a.get("source_ip"),
                    "detector": a.get("detector"),
                    "severity": a.get("severity"),
                    "desc": a.get("description"),
                    "mitre": f"{a.get('technique_name')} ({a.get('technique_id')})"
                })

            prompt = (
                f"You are a Senior SOC Analyst reviewing log analysis reports from LogGuardian AI.\n"
                f"Log File: {filename}\n"
                f"Log Type: {log_type}\n"
                f"Overall Security Health Score: {score}/100\n"
                f"System Risk Rating: {rating}\n"
                f"Detected Alerts (JSON array): {summary_alerts}\n\n"
                f"Please generate a complete, professional, production-ready markdown security investigation summary. "
                f"Include an Executive Incident Summary, Threat Analysis & Findings, MITRE ATT&CK details, Containment Actions (Immediate Playbook), and Long-Term Remediation suggestions."
            )

            data = {
                "model": "gpt-4-turbo",
                "messages": [
                    {"role": "system", "content": "You are a professional Cyber Threat Hunter and Incident Responder writing high-quality report briefs."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }

            res = requests.post(url, json=data, headers=headers, timeout=15)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
            else:
                log.warning(f"OpenAI API call failed (HTTP {res.status_code}), falling back to local expert system.")
        except Exception as e:
            log.error(f"Error querying OpenAI API: {e}")
            
        return self._generate_local_expert_summary(filename, log_type, score, rating, alerts)

    def _query_gemini(self, filename: str, log_type: str, score: int, rating: str, alerts: List[Dict[str, Any]]) -> str:
        """Queries Gemini API to generate the investigation summary."""
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
            headers = {"Content-Type": "application/json"}
            
            summary_alerts = []
            for a in alerts[:30]:
                summary_alerts.append({
                    "timestamp": a.get("timestamp"),
                    "ip": a.get("source_ip"),
                    "detector": a.get("detector"),
                    "severity": a.get("severity"),
                    "desc": a.get("description"),
                    "mitre": f"{a.get('technique_name')} ({a.get('technique_id')})"
                })

            prompt = (
                f"You are a Senior Security Analyst reviewing log analysis reports.\n"
                f"File: {filename} ({log_type})\n"
                f"Health Score: {score}/100 (Risk: {rating})\n"
                f"Incidents: {summary_alerts}\n\n"
                f"Write a professional markdown investigation summary containing:\n"
                f"1. Executive Incident Summary\n"
                f"2. Threat Analysis & Findings (MITRE ATT&CK mapping)\n"
                f"3. Containment Actions (Immediate Playbook)\n"
                f"4. Long-Term Remediation & System Hardening."
            )

            data = {
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2
                }
            }

            res = requests.post(url, json=data, headers=headers, timeout=15)
            if res.status_code == 200:
                parts = res.json()["candidates"][0]["content"]["parts"]
                return parts[0]["text"]
            else:
                log.warning(f"Gemini API call failed (HTTP {res.status_code}), falling back to local expert system.")
        except Exception as e:
            log.error(f"Error querying Gemini API: {e}")
            
        return self._generate_local_expert_summary(filename, log_type, score, rating, alerts)
