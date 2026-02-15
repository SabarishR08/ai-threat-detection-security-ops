"""
SOC Analyzer Routes - Log analysis with AI
"""
import logging
from flask import Blueprint, render_template, request, jsonify
from backend.soc_analyzer import analyze_logs
from backend.extensions import db
from backend.models import ThreatLog

soc_bp = Blueprint("soc", __name__)

@soc_bp.route("/soc-analyzer", methods=["GET", "POST"])
def soc_analyzer():
    if request.method == "POST":
        log_text = request.form.get("log_text", "")

        # File upload support
        file = request.files.get("log_file")
        if file and file.filename:
            log_text = file.read().decode(errors="ignore")

        if not log_text:
            return jsonify({"error": "No logs received"})

        # Run AI analysis
        result = analyze_logs(log_text)

        # Save to database
        log_entry = ThreatLog(
            category="soc",
            url="SOC Analysis",
            flagged_reason=result.get("ai_analysis", {}).get("summary", "SOC analysis completed"),
            severity=result.get("ai_analysis", {}).get("severity", "Low")
        )
        db.session.add(log_entry)
        try:
            db.session.commit()
        except Exception as db_err:
            logging.error(f"Database commit error: {db_err}")
            db.session.rollback()

        return jsonify(result)

    return render_template("soc_analyzer.html", active_page="soc-analyzer")
