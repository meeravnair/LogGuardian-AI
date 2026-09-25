"""
LogGuardian AI Configuration Module.
Defines regex patterns, rules, threat signatures, severity scores,
and MITRE ATT&CK mapping tables.
"""

import os
from typing import Dict, Any, List

# Base Directory of the application
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database settings
DATABASE_PATH = os.path.join(BASE_DIR, "database", "scans.db")

# Report settings
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
SAMPLE_LOGS_DIR = os.path.join(BASE_DIR, "sample_logs")

# Developer info
DEVELOPER_INFO = {
    "name": "Meera V Nair",
    "github": "https://github.com/meeravnair",
    "role": "Lead Security Architect & DevSecOps Engineer"
}

# Detection thresholds
THRESHOLDS = {
    "brute_force": {
        "failures_threshold": 5,      # number of failures
        "window_seconds": 300,        # sliding window of 5 minutes
    },
    "dos": {
        "requests_threshold": 100,    # number of requests
        "window_seconds": 60,         # sliding window of 1 minute
    },
    "auth_anomaly": {
        "success_after_failure_window": 600  # 10 minutes
    }
}

# Severity point weights (used to compute overall risk score)
SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 8,
    "CRITICAL": 10
}

# MITRE ATT&CK Mapping database
# Maps detector types to MITRE Tactic and Technique
MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force"
    },
    "sql_injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application"
    },
    "xss": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application"
    },
    "directory_traversal": {
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials"
    },
    "command_injection": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter"
    },
    "file_inclusion": {
        "tactic": "Execution",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution"
    },
    "scanner_detection": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning"
    },
    "user_agents": {
        "tactic": "Defense Evasion",
        "technique_id": "T1036",
        "technique_name": "Masquerading"
    },
    "dos_detector": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service"
    },
    "auth_anomaly": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique_name": "Remote Services"
    }
}

# Malicious patterns/payload signatures
THREAT_SIGNATURES: Dict[str, List[str]] = {
    "sql_injection": [
        r"(?i)(union\s+select)",
        r"(?i)(select\s+.*\s+from)",
        r"(?i)(insert\s+into)",
        r"(?i)(update\s+.*\s+set)",
        r"(?i)(delete\s+from)",
        r"(?i)(or\s+\d+=\d+)",
        r"(?i)(and\s+\d+=\d+)",
        r"(?i)(information_schema)",
        r"(?i)(concat\()",
        r"(?i)(group_concat)",
        r"(?i)(order\s+by\s+\d+)",
        r"(?i)(admin'\s*--)",
        r"(?i)(admin'\s*#)",
        r"(?i)('or'1'='1)",
        r"(?i)(benchmark\()",
        r"(?i)(pg_sleep\()",
        r"(?i)(sleep\(\d+\))",
        r"(?i)(waitfor\s+delay)"
    ],
    "xss": [
        r"(?i)(<script>)",
        r"(?i)(<\/script>)",
        r"(?i)(javascript:)",
        r"(?i)(onload=)",
        r"(?i)(onerror=)",
        r"(?i)(onmouseover=)",
        r"(?i)(alert\()",
        r"(?i)(confirm\()",
        r"(?i)(prompt\()",
        r"(?i)(document\.cookie)",
        r"(?i)(window\.location)",
        r"(?i)(String\.fromCharCode)",
        r"(?i)(eval\()",
        r"(?i)(base64\()",
        r"(?i)(<iframe)",
        r"(?i)(<svg)"
    ],
    "directory_traversal": [
        r"\.\.\/",
        r"\.\.\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"(?i)(etc\/passwd)",
        r"(?i)(etc\/shadow)",
        r"(?i)(boot\.ini)",
        r"(?i)(win\.ini)",
        r"(?i)(windows\/system32)"
    ],
    "command_injection": [
        r"(?i)(;\s*whoami)",
        r"(?i)(\|\s*whoami)",
        r"(?i)(&\s*whoami)",
        r"(?i)(;\s*id)",
        r"(?i)(;\s*uname)",
        r"(?i)(;\s*cat\s+)",
        r"(?i)(\|\s*cat\s+)",
        r"(?i)(;\s*ping\s+)",
        r"(?i)(/bin/bash)",
        r"(?i)(/bin/sh)",
        r"(?i)(cmd\.exe)",
        r"(?i)(powershell\.exe)",
        r"(?i)(wget\s+http)",
        r"(?i)(curl\s+http)",
        r"(?i)(python\s+-c)",
        r"(?i)(perl\s+-e)"
    ],
    "file_inclusion": [
        r"(?i)(file:\/\/)",
        r"(?i)(http:\/\/)",
        r"(?i)(https:\/\/)",
        r"(?i)(ftp:\/\/)",
        r"(?i)(php:\/\/filter)",
        r"(?i)(php:\/\/input)",
        r"(?i)(data:\/\/)",
        r"(?i)(expect:\/\/)"
    ],
    "scanners": [
        r"(?i)(nmap)",
        r"(?i)(nikto)",
        r"(?i)(sqlmap)",
        r"(?i)(acunetix)",
        r"(?i)(nessus)",
        r"(?i)(netsparker)",
        r"(?i)(dirbuster)",
        r"(?i)(gobuster)",
        r"(?i)(w3af)",
        r"(?i)(openvas)"
    ],
    "sensitive_paths": [
        r"(?i)(wp-config)",
        r"(?i)(\.git\/)",
        r"(?i)(\.env)",
        r"(?i)(config\.php)",
        r"(?i)(wp-admin)",
        r"(?i)(phpmyadmin)",
        r"(?i)(backup\.zip)",
        r"(?i)(backup\.sql)",
        r"(?i)(dump\.sql)",
        r"(?i)(\.aws\/credentials)",
        r"(?i)(id_rsa)"
    ],
    "suspicious_user_agents": [
        r"(?i)(curl)",
        r"(?i)(wget)",
        r"(?i)(python-requests)",
        r"(?i)(libwww)",
        r"(?i)(lwp-trivial)",
        r"(?i)(nmap)",
        r"(?i)(nikto)",
        r"(?i)(sqlmap)"
    ]
}
