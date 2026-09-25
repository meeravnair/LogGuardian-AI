"""
LogGuardian AI Web Portal Backend.
Implements Flask routing, scans triggers, metrics computation, search capabilities,
and report dispatchers.
"""

import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
from werkzeug.utils import secure_filename

from config import DATABASE_PATH, DEVELOPER_INFO
from logger import log
from database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan,
    get_scan_alerts,
    get_scan_logs,
    get_scan_metrics,
    get_global_metrics,
    delete_scan
)
from core.parser import LogParser
from core.analyzer import LogAnalyzer
from core.risk_engine import RiskEngine
from core.ai_summary import AISummaryGenerator
from core.timeline import TimelineGenerator
from core.report_generator import ReportGenerator
from utils import format_bytes, get_threat_label

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "logguardian_secure_portal_key_2026")

# Folder to store uploaded logs temporarily
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize database on startup
with app.app_context():
    init_db()

@app.route("/")
@app.route("/index")
def index():
    """Index page - lists historical scans, global metrics, and holds the file upload panel."""
    try:
        scans = get_all_scans(limit=10)
        global_stats = get_global_metrics()
    except Exception as e:
        log.error(f"Error loading index data: {e}")
        scans = []
        global_stats = {
            "total_scans": 0, "total_alerts": 0, "total_logs": 0, "avg_security_score": 100.0,
            "alerts_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, "scans_by_type": {}
        }
        
    return render_template(
        "index.html",
        scans=scans,
        global_stats=global_stats,
        dev_info=DEVELOPER_INFO
    )

@app.route("/scan", methods=["POST"])
def scan_log():
    """Processes uploaded log file through parsing, analysis, and scoring engines."""
    if "log_file" not in request.files:
        flash("No file part in the request", "error")
        return redirect(url_for("index"))

    file = request.files["log_file"]
    if file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("index"))

    log_type = request.form.get("log_type", "auto")

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        
        file_size_bytes = os.path.getsize(filepath)

        log.info(f"Portal received log asset: {filename} ({format_bytes(file_size_bytes)}) for '{log_type}' scan.")

        try:
            # 1. Parsing
            parser = LogParser()
            if log_type == "auto":
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    sample_lines = f.readlines()
                detected_type = parser.detect_format(sample_lines)
            else:
                detected_type = log_type

            normalized_entries = parser.parse(filepath, detected_type)

            if not normalized_entries:
                flash("Log file parsing failed: No valid log lines detected or formatted incorrectly.", "error")
                os.remove(filepath)
                return redirect(url_for("index"))

            # 2. Threat Analysis
            analyzer = LogAnalyzer()
            alerts = analyzer.analyze_entries([e.to_dict() for e in normalized_entries])

            # 3. Scoring
            security_score, risk_rating = RiskEngine.calculate_score(alerts)

            # 4. AI-assisted investigation summary
            ai_gen = AISummaryGenerator()
            ai_summary = ai_gen.generate_summary(
                filename=filename,
                log_type=detected_type,
                security_score=security_score,
                risk_rating=risk_rating,
                alerts=alerts
            )

            # 5. Save to database history
            scan_id = str(uuid.uuid4())
            save_scan(
                scan_id=scan_id,
                filename=filename,
                file_size=file_size_bytes,
                log_type=detected_type,
                security_score=security_score,
                risk_rating=risk_rating,
                total_entries=len(normalized_entries),
                alerts=alerts,
                normalized_entries=[e.to_dict() for e in normalized_entries],
                ai_summary=ai_summary
            )

            # Cleanup uploaded file
            os.remove(filepath)

            flash("Scan completed successfully!", "success")
            return redirect(url_for("dashboard", scan_id=scan_id))

        except Exception as e:
            log.exception(f"Exception during web portal scan flow: {e}")
            flash(f"An error occurred during scanning: {str(e)}", "error")
            if os.path.exists(filepath):
                os.remove(filepath)
            return redirect(url_for("index"))

    return redirect(url_for("index"))

@app.route("/dashboard/<scan_id>")
def dashboard(scan_id):
    """Scan Analysis view - shows the detailed incident dashboard."""
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan ID not found in history.", "error")
        return redirect(url_for("index"))

    alerts = get_scan_alerts(scan_id)
    metrics = get_scan_metrics(scan_id)
    
    # Generate chronological timeline
    timeline_gen = TimelineGenerator()
    timeline = timeline_gen.generate_timeline(alerts)

    return render_template(
        "dashboard.html",
        scan=scan,
        alerts=alerts,
        metrics=metrics,
        timeline=timeline,
        dev_info=DEVELOPER_INFO
    )

@app.route("/report/<scan_id>/<file_format>")
def download_report(scan_id, file_format):
    """Generates and serves downloadable reports on-the-fly."""
    scan = get_scan(scan_id)
    if not scan:
        return "Scan not found", 404

    alerts = get_scan_alerts(scan_id)
    
    timeline_gen = TimelineGenerator()
    timeline = timeline_gen.generate_timeline(alerts)

    report_gen = ReportGenerator(reports_dir=os.path.join(app.root_path, "reports"))
    
    # Generate the requested formats
    paths = report_gen.generate_all(scan, alerts, timeline)
    
    target_path = paths.get(file_format.lower())
    if target_path and os.path.exists(target_path):
        mimetypes = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json",
            "csv": "text/csv"
        }
        return send_file(
            target_path,
            mimetype=mimetypes.get(file_format.lower(), "application/octet-stream"),
            as_attachment=True,
            download_name=os.path.basename(target_path)
        )
    
    return "Format not supported or failed to generate", 400

@app.route("/delete/<scan_id>", methods=["POST"])
def remove_scan(scan_id):
    """Deletes a scan run from DB history."""
    if delete_scan(scan_id):
        flash("Scan run deleted successfully.", "success")
    else:
        flash("Failed to delete scan from history.", "error")
    return redirect(url_for("index"))

@app.route("/search_history")
def search_history():
    """Searches scan records in history database."""
    query = request.args.get("query", "")
    scans = get_all_scans(limit=50, search_query=query)
    
    # Convert list of rows to JSON-serializable list
    serializable_scans = []
    for s in scans:
        serializable_scans.append({
            "id": s["id"],
            "filename": s["filename"],
            "timestamp": s["timestamp"],
            "log_type": s["log_type"],
            "security_score": s["security_score"],
            "risk_rating": s["risk_rating"],
            "total_alerts": s["total_alerts"]
        })
    return jsonify(serializable_scans)

@app.route("/api/scan_details/<scan_id>")
def scan_details_api(scan_id):
    """Fetches details & metrics of a scan in JSON format (useful for Javascript visualizations)."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
        
    metrics = get_scan_metrics(scan_id)
    return jsonify({
        "scan": dict(scan),
        "metrics": metrics
    })

# Template Filters
@app.template_filter('threat_label')
def filter_threat_label(value):
    """Template filter to get threat label."""
    return get_threat_label(value)

@app.template_filter('format_size')
def filter_format_size(value):
    """Template filter to format byte size."""
    return format_bytes(value)

if __name__ == "__main__":
    # Start the Flask web application
    log.info("Starting LogGuardian AI Web Interface...")
    app.run(host="127.0.0.1", port=5000, debug=True)
