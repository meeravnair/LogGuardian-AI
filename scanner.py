"""
LogGuardian AI Command Line Interface (CLI) Scanner.
Allows threat hunters and security engineers to parse and analyze logs
from the console, outputting ASCII alerts tables and generating reports.
"""

import os
import argparse
import uuid
from typing import Dict, Any, List
from colorama import Fore, Style, init
from tabulate import tabulate

from config import DEVELOPER_INFO
from logger import log
from database import init_db, save_scan
from core.parser import LogParser
from core.analyzer import LogAnalyzer
from core.risk_engine import RiskEngine
from core.ai_summary import AISummaryGenerator
from core.timeline import TimelineGenerator
from core.report_generator import ReportGenerator
from utils import format_bytes, get_threat_label

# Initialize Colorama
init(autoreset=True)

ASCII_BANNER = rf"""
{Fore.CYAN}    __                  ______                      __ _               ___   ____
   / /   ____  ____ _  / ____/__  ______ __________/ /(_)___ _____    /   | /  _/
  / /   / __ \/ __ `/ / / __ / / / / __ `/ ___/ __  // / __ `/ __ \  / /| | / /  
 / /___/ /_/ / /_/ / / /_/ // /_/ / /_/ / /  / /_/ // / /_/ / / / / / ___ |/ /   
/_____/\____/\__, /  \____/ \__,_/\__,_/_/   \__,_//_/\__,_/_/ /_//_/  |_/___/   
            /____/                                                               
{Fore.YELLOW}  >> Intelligent Security Log Analysis & Threat Detection Platform
  >> Developed by: {DEVELOPER_INFO['name']} | GitHub: {DEVELOPER_INFO['github']}
  {Fore.RED}==============================================================================
"""

def parse_arguments():
    """Parses CLI arguments."""
    parser = argparse.ArgumentParser(
        description="LogGuardian AI - Automated Security Log Analysis Scanner CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Absolute path to the log file to analyze"
    )
    parser.add_argument(
        "-t", "--type",
        default="auto",
        choices=["auto", "apache_nginx_access", "apache_error", "linux_auth", "firewall_iptables", "custom"],
        help="Log file format profile (default: auto-detect)"
    )
    parser.add_argument(
        "-o", "--output",
        default="reports",
        help="Output directory for generated reports (default: 'reports')"
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Do not save scan results to the historical SQLite database"
    )
    return parser.parse_args()

def main():
    """Main execution entry point of the CLI scanner."""
    print(ASCII_BANNER)
    args = parse_arguments()

    if not os.path.exists(args.file):
        print(f"{Fore.RED}[-] Error: Target log file '{args.file}' not found.")
        return

    file_size_bytes = os.path.getsize(args.file)
    filename = os.path.basename(args.file)

    log.info(f"Initiating security scan on log asset: {filename} ({format_bytes(file_size_bytes)})")

    # 1. Parse log file
    parser = LogParser()
    try:
        # Determine format
        if args.type == "auto":
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                sample_lines = f.readlines()
            log_type = parser.detect_format(sample_lines)
        else:
            log_type = args.type

        normalized_entries = parser.parse(args.file, log_type)
    except Exception as e:
        log.critical(f"Log parsing phase failed: {e}")
        return

    if not normalized_entries:
        log.warning("No parseable log lines recovered. Exiting.")
        return

    # 2. Threat Analysis
    analyzer = LogAnalyzer()
    try:
        alerts = analyzer.analyze_entries([e.to_dict() for e in normalized_entries])
    except Exception as e:
        log.critical(f"Threat analysis phase failed: {e}")
        return

    # 3. Risk Calculation
    try:
        security_score, risk_rating = RiskEngine.calculate_score(alerts)
    except Exception as e:
        log.critical(f"Risk calculation phase failed: {e}")
        return

    # 4. Generate AI summary
    log.info("Generating security analysis narrative report...")
    ai_gen = AISummaryGenerator()
    ai_summary = ai_gen.generate_summary(
        filename=filename,
        log_type=log_type,
        security_score=security_score,
        risk_rating=risk_rating,
        alerts=alerts
    )

    # 5. Timeline Generation
    timeline_gen = TimelineGenerator()
    timeline = timeline_gen.generate_timeline(alerts)

    # Save to SQLite unless skipped
    scan_id = str(uuid.uuid4())
    if not args.no_db:
        try:
            init_db()
            save_scan(
                scan_id=scan_id,
                filename=filename,
                file_size=file_size_bytes,
                log_type=log_type,
                security_score=security_score,
                risk_rating=risk_rating,
                total_entries=len(normalized_entries),
                alerts=alerts,
                normalized_entries=[e.to_dict() for e in normalized_entries],
                ai_summary=ai_summary
            )
        except Exception as e:
            log.error(f"Failed to record scan run history: {e}")

    # 6. Generate Reports
    log.info("Exporting assessment briefs (PDF, HTML, JSON, CSV)...")
    report_gen = ReportGenerator(reports_dir=args.output)
    scan_data = {
        "id": scan_id,
        "filename": filename,
        "file_size": file_size_bytes,
        "log_type": log_type,
        "security_score": security_score,
        "risk_rating": risk_rating,
        "total_entries": len(normalized_entries),
        "ai_summary": ai_summary
    }
    
    paths = report_gen.generate_all(scan_data, alerts, timeline)

    # Output CLI visual results
    print(f"\n{Fore.GREEN}===================== SCAN RESULTS SUMMARY =====================")
    
    # Summary Table
    summary_table = [
        ["Log File", filename],
        ["Log Size", format_bytes(file_size_bytes)],
        ["Log Profile", log_type.upper()],
        ["Total Lines Processed", len(normalized_entries)],
        ["Security Incidents Flagged", len(alerts)],
        ["System Health Score", f"{security_score}/100"],
        ["Risk Assessment", risk_rating]
    ]
    print(tabulate(summary_table, tablefmt="grid"))

    # Threat Severity Color mapping
    sev_colors = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.LIGHTRED_EX,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.GREEN
    }

    if alerts:
        print(f"\n{Fore.RED}[!] FLAG TARGETED SECURITY THREATS:")
        threat_headers = ["Timestamp", "Adversary IP", "Attack Category", "Severity", "MITRE ID", "Incident Details"]
        threat_rows = []
        
        for a in alerts[:25]: # limit output
            sev = a.get("severity", "MEDIUM")
            color = sev_colors.get(sev, Fore.WHITE)
            threat_rows.append([
                a.get("timestamp"),
                a.get("source_ip", "N/A"),
                get_threat_label(a.get("detector")),
                f"{color}{sev}{Style.RESET_ALL}",
                a.get("technique_id", "N/A"),
                a.get("description")[:65] + "..." if len(a.get("description", "")) > 65 else a.get("description")
            ])
        print(tabulate(threat_rows, headers=threat_headers, tablefmt="simple"))
        
        if len(alerts) > 25:
            print(f"\n{Fore.YELLOW}... and {len(alerts) - 25} other incidents (check exported files for full details)")

    # Print Export Paths
    print(f"\n{Fore.CYAN}[+] EXPORTED ASSESSMENT FILES:")
    for fmt, path in paths.items():
        print(f"  - {fmt.upper()}: {Fore.LIGHTGREEN_EX}{os.path.abspath(path)}")
    print(f"{Fore.GREEN}================================================================\n")

if __name__ == "__main__":
    main()
