"""
LogGuardian AI Report Generator Module.
Generates comprehensive analysis reports in PDF, HTML, JSON, and CSV formats.
Includes custom ReportLab formatting for highly professional PDF output.
"""

import os
import csv
import json
import re
from datetime import datetime
from typing import List, Dict, Any
from logger import log
from utils import get_threat_label

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas

# Palette definition
PRIMARY = colors.HexColor("#0f172a")    # Slate 900
SECONDARY = colors.HexColor("#1e293b")  # Slate 800
ACCENT = colors.HexColor("#6366f1")     # Indigo 500
BORDER_COLOR = colors.HexColor("#e2e8f0")
BG_LIGHT = colors.HexColor("#f8fafc")

class NumberedCanvas(canvas.Canvas):
    """Custom canvas to calculate total page count and add headers/footers dynamically."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b")) # Slate 500
        
        # Header (on all pages except page 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "LogGuardian AI - Automated Security Assessment Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        # Footer (on all pages)
        footer_y = 40
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 52, 558, 52)
        
        # Developer info on footer left, Page numbers on right
        self.drawString(54, footer_y, "Developer: Meera V Nair | GitHub: https://github.com/meeravnair")
        self.drawRightString(558, footer_y, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class ReportGenerator:
    """
    Export manager generating SIEM-compliant, formatted outputs.
    """

    def __init__(self, reports_dir: str = "reports") -> None:
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_all(self, scan_data: Dict[str, Any], alerts: List[Dict[str, Any]], timeline: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generates PDF, HTML, JSON, and CSV reports.
        
        Args:
            scan_data: Global scan metrics dictionary.
            alerts: List of deduplicated alerts.
            timeline: Chronological timeline structure.
            
        Returns:
            A dictionary containing output paths.
        """
        scan_id = scan_data.get("id")
        timestamp_clean = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"logguardian_{timestamp_clean}_{scan_id[:8]}"

        paths = {
            "json": os.path.join(self.reports_dir, f"{base_filename}.json"),
            "csv": os.path.join(self.reports_dir, f"{base_filename}.csv"),
            "html": os.path.join(self.reports_dir, f"{base_filename}.html"),
            "pdf": os.path.join(self.reports_dir, f"{base_filename}.pdf")
        }

        self.generate_json(paths["json"], scan_data, alerts, timeline)
        self.generate_csv(paths["csv"], alerts)
        self.generate_html(paths["html"], scan_data, alerts, timeline)
        self.generate_pdf(paths["pdf"], scan_data, alerts)

        return paths

    def generate_json(self, path: str, scan_data: Dict[str, Any], alerts: List[Dict[str, Any]], timeline: List[Dict[str, Any]]) -> None:
        """Exports raw findings to standard JSON."""
        output = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "developer": "Meera V Nair",
                "github": "https://github.com/meeravnair"
            },
            "scan_data": scan_data,
            "alerts": alerts,
            "timeline": timeline
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4)
        log.info(f"JSON Report exported to: {path}")

    def generate_csv(self, path: str, alerts: List[Dict[str, Any]]) -> None:
        """Exports alerts list as CSV."""
        fields = ["timestamp", "source_ip", "username", "detector", "severity", "tactic", "technique_id", "technique_name", "description", "payload", "occured_count"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for alert in alerts:
                # filter keys to csv fields only
                row = {k: alert.get(k, "") for k in fields}
                writer.writerow(row)
        log.info(f"CSV Report exported to: {path}")

    def generate_html(self, path: str, scan_data: Dict[str, Any], alerts: List[Dict[str, Any]], timeline: List[Dict[str, Any]]) -> None:
        """Generates self-contained, responsive HTML assessment dashboard."""
        
        # Build alert table rows
        alert_rows = ""
        for a in alerts:
            sev_class = a.get('severity', 'MEDIUM').lower()
            payload_safe = re.sub(r'["\'<>]+', '', a.get('payload', '') or '')
            payload_html = f"<pre><code>{payload_safe[:180]}...</code></pre>" if payload_safe else ""
            alert_rows += f"""
            <tr class="severity-{sev_class}">
                <td>{a.get('timestamp')}</td>
                <td><strong>{a.get('source_ip', 'N/A')}</strong></td>
                <td><span class="detector-badge">{get_threat_label(a.get('detector'))}</span></td>
                <td><span class="badge badge-{sev_class}">{a.get('severity')}</span></td>
                <td>
                    <strong>{a.get('description')}</strong>
                    {payload_html}
                </td>
                <td><span class="mitre-tag">{a.get('technique_id', 'N/A')} - {a.get('technique_name', 'N/A')}</span></td>
            </tr>
            """

        # Convert markdown summary to basic HTML format for rendering
        ai_summary_html = ""
        if scan_data.get("ai_summary"):
            raw_summary = scan_data.get("ai_summary")
            # Replace markdown headers with HTML headers
            html_summary = re.sub(r'^###\s+(.*)$', r'<h4>\1</h4>', raw_summary, flags=re.MULTILINE)
            html_summary = re.sub(r'^####\s+(.*)$', r'<h5>\1</h5>', html_summary, flags=re.MULTILINE)
            html_summary = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_summary)
            html_summary = re.sub(r'^-\s+(.*)$', r'<li>\1</li>', html_summary, flags=re.MULTILINE)
            html_summary = html_summary.replace('\n', '<br>')
            ai_summary_html = html_summary
        else:
            ai_summary_html = "<p>No AI analysis summary generated.</p>"

        # Beautiful Dark-themed HTML Report template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LogGuardian AI Threat Assessment Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-glow: #6366f1;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
        }}
        body {{
            background: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.2em;
            color: var(--text-primary);
            text-shadow: 0 0 10px rgba(99, 102, 241, 0.4);
        }}
        .header p {{
            margin: 5px 0 0 0;
            color: var(--text-secondary);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .meta-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        .meta-card h3 {{
            margin: 0 0 10px 0;
            font-size: 0.9em;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .meta-card p {{
            margin: 0;
            font-size: 1.8em;
            font-weight: bold;
        }}
        .risk-CRITICAL {{ color: var(--critical); }}
        .risk-HIGH {{ color: var(--high); }}
        .risk-MEDIUM {{ color: var(--medium); }}
        .risk-LOW {{ color: var(--low); }}
        .risk-SECURE {{ color: #10b981; }}
        
        .score-box {{
            font-size: 2.2em !important;
            text-shadow: 0 0 15px rgba(99, 102, 241, 0.6);
        }}
        .summary-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 5px solid var(--accent-glow);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 40px;
            line-height: 1.6;
        }}
        .summary-card h4 {{
            margin-top: 0;
            color: var(--text-primary);
            font-size: 1.2em;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 40px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        th {{
            background: rgba(15, 23, 42, 0.8);
            color: var(--text-primary);
            text-align: left;
            padding: 15px;
            font-weight: 600;
        }}
        td {{
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}
        tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}
        pre {{
            margin: 5px 0 0 0;
            background: rgba(0, 0, 0, 0.3);
            padding: 8px;
            border-radius: 6px;
            border: 1px solid #1e293b;
            color: #38bdf8;
            font-size: 0.85em;
            overflow-x: auto;
        }}
        .badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            display: inline-block;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
        
        .mitre-tag {{
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.8em;
            font-family: monospace;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }}
        .detector-badge {{
            font-weight: 600;
            color: #38bdf8;
        }}
        .footer {{
            text-align: center;
            color: var(--text-secondary);
            margin-top: 60px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
            font-size: 0.9em;
        }}
        .footer a {{
            color: var(--accent-glow);
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ LogGuardian AI</h1>
                <p>Intelligent Security Log Analysis & Threat Detection Platform</p>
            </div>
            <div style="text-align: right;">
                <span class="mitre-tag">SIEM COMPLIANT REPORT</span>
                <p style="margin-top: 5px; font-size: 0.85em;">Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <h3>Target Log File</h3>
                <p style="font-size: 1.3em; margin-top: 10px; word-break: break-all;">{scan_data.get('filename')}</p>
            </div>
            <div class="meta-card">
                <h3>Log Format Profile</h3>
                <p style="font-size: 1.3em; margin-top: 10px; text-transform: uppercase;">{scan_data.get('log_type')}</p>
            </div>
            <div class="meta-card">
                <h3>Security Health Score</h3>
                <p class="score-box risk-{scan_data.get('risk_rating')}">{scan_data.get('security_score')}/100</p>
            </div>
            <div class="meta-card">
                <h3>Calculated Threat Level</h3>
                <p class="risk-{scan_data.get('risk_rating')}">{scan_data.get('risk_rating')}</p>
            </div>
        </div>

        <div class="summary-card">
            {ai_summary_html}
        </div>

        <h2>🚨 Detected Security Events ({len(alerts)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%">Timestamp</th>
                    <th style="width: 15%">Source IP</th>
                    <th style="width: 15%">Attack Vector</th>
                    <th style="width: 10%">Severity</th>
                    <th style="width: 30%">Incident Description</th>
                    <th style="width: 15%">MITRE ATT&CK Mapping</th>
                </tr>
            </thead>
            <tbody>
                {alert_rows if alert_rows else '<tr><td colspan="6" style="text-align:center;">No threat alerts detected in this log file.</td></tr>'}
            </tbody>
        </table>

        <div class="footer">
            <p>LogGuardian AI &copy; 2026. Designed and developed by <strong>Meera V Nair</strong> | GitHub: <a href="https://github.com/meeravnair" target="_blank">meeravnair</a></p>
        </div>
    </div>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        log.info(f"HTML Report exported to: {path}")

    def generate_pdf(self, path: str, scan_data: Dict[str, Any], alerts: List[Dict[str, Any]]) -> None:
        """
        Generates a professional, print-ready PDF threat assessment report.
        Uses ReportLab tables and flowables.
        """
        # Document Setup
        doc = SimpleDocTemplate(
            path,
            pagesize=letter,
            rightMargin=54,
            leftMargin=54,
            topMargin=54,
            bottomMargin=70
        )

        # Style Sheets setup
        base_styles = getSampleStyleSheet()
        
        # Modify existing Styles cleanly, or define unique names
        title_style = ParagraphStyle(
            name="DocTitle",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=PRIMARY,
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            name="DocSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=20
        )

        section_heading = ParagraphStyle(
            name="SectionHeading",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=PRIMARY,
            spaceBefore=15,
            spaceAfter=8,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            name="ReportBody",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#334155")
        )

        meta_label_style = ParagraphStyle(
            name="MetaLabel",
            parent=body_style,
            fontName="Helvetica-Bold",
            textColor=PRIMARY
        )

        code_style = ParagraphStyle(
            name="CodeStyle",
            parent=base_styles["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0284c7")
        )

        story = []

        # 1. Header Section
        story.append(Paragraph("🛡️ LogGuardian AI - Security Report", title_style))
        story.append(Paragraph("Automated Incident Analysis & Vulnerability Mapping Brief", subtitle_style))
        
        # 2. Metadata Grid (Key Info Table)
        risk_color = colors.HexColor("#10b981") # default secure green
        risk_str = scan_data.get('risk_rating', 'SECURE')
        if risk_str == "CRITICAL":
            risk_color = colors.HexColor("#ef4444")
        elif risk_str == "HIGH":
            risk_color = colors.HexColor("#f97316")
        elif risk_str == "MEDIUM":
            risk_color = colors.HexColor("#eab308")
        elif risk_str == "LOW":
            risk_color = colors.HexColor("#3b82f6")

        meta_data = [
            [
                Paragraph("Target Log File:", meta_label_style),
                Paragraph(scan_data.get('filename', ''), body_style),
                Paragraph("Security Health Score:", meta_label_style),
                Paragraph(f"<b>{scan_data.get('security_score')}/100</b>", ParagraphStyle(name="ScoreCol", parent=body_style, textColor=risk_color, fontName="Helvetica-Bold"))
            ],
            [
                Paragraph("Log Profile Type:", meta_label_style),
                Paragraph(str(scan_data.get('log_type', '')).upper(), body_style),
                Paragraph("Assessed Threat Level:", meta_label_style),
                Paragraph(f"<b>{risk_str}</b>", ParagraphStyle(name="RiskCol", parent=body_style, textColor=risk_color, fontName="Helvetica-Bold"))
            ],
            [
                Paragraph("Processed Entries:", meta_label_style),
                Paragraph(str(scan_data.get('total_entries', 0)), body_style),
                Paragraph("Total Security Alerts:", meta_label_style),
                Paragraph(str(len(alerts)), body_style)
            ]
        ]
        
        # Column widths summing to 504 (letter printable width is 8.5 * 72 - 108 = 504)
        meta_table = Table(meta_data, colWidths=[110, 142, 120, 132])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('BOX', (0, 0), (-1, -1), 1, SECONDARY),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # 3. AI Incident Investigation Summary
        story.append(Paragraph("🛡️ SOC Threat Investigation Summary", section_heading))
        
        # Simple markdown to flowable parser for AI Summary
        raw_summary = scan_data.get("ai_summary", "")
        if raw_summary:
            summary_paras = raw_summary.split("\n\n")
            for para in summary_paras:
                para = para.strip()
                if not para:
                    continue
                
                # Check for headings
                if para.startswith("###"):
                    header_text = para.replace("###", "").strip()
                    story.append(Paragraph(header_text, ParagraphStyle("H3", parent=section_heading, fontSize=11, spaceBefore=8, spaceAfter=4)))
                elif para.startswith("##"):
                    header_text = para.replace("##", "").strip()
                    story.append(Paragraph(header_text, ParagraphStyle("H2", parent=section_heading, fontSize=12, spaceBefore=10, spaceAfter=5)))
                # Check for bullet points
                elif para.startswith("-") or para.startswith("*"):
                    bullets = para.split("\n")
                    for b in bullets:
                        b_text = re.sub(r'^[-*]\s+', '', b.strip())
                        # Render bold formatting
                        b_text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', b_text)
                        b_text = re.sub(r'`(.*?)`', r'<font face="Courier">\1</font>', b_text)
                        story.append(Paragraph(f"&bull; {b_text}", ParagraphStyle("Bullet", parent=body_style, leftIndent=12, spaceAfter=3)))
                else:
                    # Regular paragraph text. Handle bolding and code blocks
                    para_text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', para)
                    para_text = re.sub(r'`(.*?)`', r'<font face="Courier">\1</font>', para_text)
                    para_text = para_text.replace("\n", "<br/>")
                    story.append(Paragraph(para_text, ParagraphStyle("Body", parent=body_style, spaceAfter=8)))
        else:
            story.append(Paragraph("No investigation summary generated.", body_style))

        story.append(Spacer(1, 15))

        # 4. Detailed Alerts Table
        story.append(Paragraph("🚨 LogGuardian AI Detections List", section_heading))
        
        # Build alert table header
        table_header = [
            Paragraph("<b>Time / Host IP</b>", ParagraphStyle("TH_IP", parent=body_style, fontName="Helvetica-Bold", textColor=colors.white)),
            Paragraph("<b>Attack Category</b>", ParagraphStyle("TH_Cat", parent=body_style, fontName="Helvetica-Bold", textColor=colors.white)),
            Paragraph("<b>Severity</b>", ParagraphStyle("TH_Sev", parent=body_style, fontName="Helvetica-Bold", textColor=colors.white)),
            Paragraph("<b>Incident Explanation / Raw IOC Payload</b>", ParagraphStyle("TH_Exp", parent=body_style, fontName="Helvetica-Bold", textColor=colors.white))
        ]
        
        table_rows = [table_header]
        
        # Limit tables to top 50 elements in PDF printout to avoid huge files
        for alert in alerts[:50]:
            ip = alert.get("source_ip", "N/A")
            ts = alert.get("timestamp", "")
            # Shorten time labels to fit columns
            clean_ts = ts.replace(" +0000", "").replace(" +0530", "")
            
            sev = alert.get("severity", "MEDIUM")
            sev_color = "#3b82f6"
            if sev == "CRITICAL":
                sev_color = "#ef4444"
            elif sev == "HIGH":
                sev_color = "#f97316"
            elif sev == "MEDIUM":
                sev_color = "#eab308"
                
            ip_col = Paragraph(f"Time: {clean_ts}<br/>IP: <b>{ip}</b>", ParagraphStyle("ColIP", parent=body_style, fontSize=8, leading=10))
            category_col = Paragraph(f"{get_threat_label(alert.get('detector'))}<br/><font size='7' color='#4f46e5'>MITRE: {alert.get('technique_id')}</font>", ParagraphStyle("ColCat", parent=body_style, fontSize=8.5, leading=10))
            severity_col = Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", ParagraphStyle("ColSev", parent=body_style, fontSize=9, fontName="Helvetica-Bold"))
            
            # Escape strings to prevent PDF generation crash
            desc = alert.get("description", "")
            payload = alert.get("payload", "")
            if payload:
                # Limit length
                short_pay = payload[:130] + "..." if len(payload) > 130 else payload
                short_pay_clean = re.sub(r'[\<\>]+', '', short_pay)
                desc_text = f"{desc}<br/><font color='#64748b' size='7.5'>IOC: {short_pay_clean}</font>"
            else:
                desc_text = desc

            desc_col = Paragraph(desc_text, ParagraphStyle("ColDesc", parent=body_style, fontSize=8, leading=11))
            
            table_rows.append([ip_col, category_col, severity_col, desc_col])

        # Widths sum to 504 (letter printable width)
        col_widths = [110, 110, 54, 230]
        
        alerts_table = Table(table_rows, colWidths=col_widths, repeatRows=1)
        alerts_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SECONDARY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        # Add table inside a Flowable list
        if len(alerts) > 50:
            story.append(alerts_table)
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<i>* Report truncated to first 50 security logs out of {len(alerts)} alerts. View full audit trail inside CSV/JSON logs.</i>", ParagraphStyle("Trunc", parent=body_style, fontSize=8, textColor=colors.HexColor("#64748b"))))
        else:
            story.append(alerts_table)

        # Build Document
        doc.build(story, canvasmaker=NumberedCanvas)
        log.info(f"PDF Report generated successfully: {path}")
