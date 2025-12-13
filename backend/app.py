import os
import json
import base64
import logging
import requests
import pytz
import threading
import time
import csv
import cv2
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from queue import Queue
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, send_file, Blueprint
from apscheduler.schedulers.background import BackgroundScheduler

from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from soc_analyzer import analyze_logs
from email_scanner import scan_emails
from utils.helpers import format_timestamp_ist
from core.email_auto_scan import run_auto_scan

from sqlalchemy import func
from services.threat_lookup_service import lookup_url, unified_check_url

from extensions import db, limiter, socketio, cors

from models import ThreatLog, Alert, BlacklistedIP

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "dashboard", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "..", "dashboard", "static"),
    static_url_path="/static"
)



# Configure app
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "threats.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Settings storage (JSON file)
SETTINGS_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(SETTINGS_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

DEFAULT_SETTINGS = {
    "email_alerts": "enabled",
    "notification_frequency": "immediate",
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "auto_scan": True,
    "log_retention": "30",
}


def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_SETTINGS, **data}
    except Exception as e:
        logging.error(f"load_settings error: {e}")
    return DEFAULT_SETTINGS.copy()


def save_settings(data: dict):
    try:
        merged = {**DEFAULT_SETTINGS, **data}
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
        return merged
    except Exception as e:
        logging.error(f"save_settings error: {e}")
        raise

# Initialize extensions
db.init_app(app)
socketio.init_app(app, cors_allowed_origins="*")
limiter.init_app(app)
cors.init_app(app)

# Expose helpers to Jinja templates
app.jinja_env.globals["format_timestamp_ist"] = format_timestamp_ist

# Create tables
with app.app_context():
    db.create_all()

load_dotenv()

IST = pytz.timezone('Asia/Kolkata')


logging.basicConfig(
    filename=r"logs\app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_ist_time():
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------------------
# Now import & register blueprints (safe - after app exists)
# ---------------------------
# Import blueprint in a try/except to prevent hard crash if file missing
try:
    from email_scanner_routes import email_scanner
    app.register_blueprint(email_scanner)
except Exception as e:
    logging.warning(f"Could not register email_scanner blueprint: {e}")

# ---------------------------
# Environment variables & DB path
# ---------------------------
# Default DB path (relative to backend/)
_db_env = os.getenv("DATABASE_URL", "sqlite:///database/threats.db")
DB_PATH = _db_env.replace("sqlite:///", "")  # sqlite path expected

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
DEBUG_MODE = os.getenv("DEBUG", "True").lower() in ("1", "true", "yes")

# Log missing keys as warnings (do not raise here to allow local dev)
if not VIRUSTOTAL_API_KEY:
    logging.warning("Missing VirusTotal API Key in .env — some features will be disabled.")
if not BREVO_API_KEY:
    logging.warning("Missing Brevo API Key in .env — email alerts will not be sent.")
if not ALERT_EMAIL:
    logging.warning("Missing ALERT_EMAIL in .env — alert email destination not set.")
if not SENDER_EMAIL:
    logging.warning("Missing SENDER_EMAIL in .env — sender email not set.")

# ---------------------------
# APScheduler for auto-scan polling
# ---------------------------
scheduler = BackgroundScheduler()
scheduler.start()

def schedule_auto_scan():
    """Schedule the Gmail auto-scan job (every 5 minutes)."""
    def auto_scan_job():
        with app.app_context():
            run_auto_scan(app.app_context, socketio, analyze_email_for_scan)
    
    scheduler.add_job(
        func=auto_scan_job,
        trigger="interval",
        minutes=5,
        id="email_auto_scan",
        name="Gmail Auto-Scan",
        replace_existing=True
    )
    logging.info("Email auto-scan job scheduled (every 5 minutes)")

def analyze_email_for_scan(subject, body, from_addr, auto_scan=False):
    """Wrapper to analyze email from auto-scan."""
    try:
        # Run through email_scanner pipeline
        result = scan_emails(subject, body)
        return {
            "is_phishing": result.get("is_phishing", False),
            "severity": "High" if result.get("is_phishing") else "Low",
            "from": from_addr,
            "auto_scan": auto_scan
        }
    except Exception as e:
        logging.error(f"Error analyzing email: {e}")
        return {"is_phishing": False, "severity": "Low", "error": str(e)}

# ---------------------------
# Pygame initialization (safe)
# ---------------------------
try:
    import pygame
    pygame.mixer.init()
    _pygame_ok = True
except Exception as e:
    logging.warning(f"Pygame audio init failed or not available: {e}")
    _pygame_ok = False

# Cooldown timer for alert sound
last_alert_time = 0

# ---------------------------
# Auto cleanup of old logs (run once at startup)
# ---------------------------
def cleanup_old_logs():
    try:
        cutoff_date = datetime.now() - timedelta(days=30)
        ThreatLog.query.filter(ThreatLog.timestamp < cutoff_date).delete()
        db.session.commit()
    except Exception as e:
        logging.error(f"cleanup_old_logs error: {e}")

try:
    cleanup_old_logs()
except Exception:
    pass

# ---------------------------
# Middleware to block malicious IPs
# ---------------------------

@app.before_request
def block_malicious_ips():
    try:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if BlacklistedIP.query.filter_by(ip_address=client_ip).first():
            logging.warning(f"Blocked access from malicious IP: {client_ip}")
            return jsonify({"error": "Access Denied - Malicious IP detected"}), 403
    except Exception as e:
        logging.error(f"block_malicious_ips error: {e}")
        # Don't break requests if DB check fails
        return None

# ---------------------------
# Brevo Email Alert Function
# ---------------------------
def send_brevo_email(client_ip, url, status, severity):
    if not BREVO_API_KEY or not ALERT_EMAIL or not SENDER_EMAIL:
        logging.info("Skipping Brevo email — API key / addresses not configured")
        return False
    try:
        brevo_url = "https://api.brevo.com/v3/smtp/email"
        payload = {
            "sender": {"name": "Threat Detection System", "email": SENDER_EMAIL},
            "to": [{"email": ALERT_EMAIL}],
            "subject": f"🚨 Malicious URL Detected - Severity: {severity}",
            "htmlContent": (
                f"<h1>🚨 Malicious URL Detected</h1>"
                f"<p><strong>Client IP:</strong> {client_ip}</p>"
                f"<p><strong>URL:</strong> {url}</p>"
                f"<p><strong>Status:</strong> {status}</p>"
                f"<p><strong>Severity:</strong> {severity}</p>"
            )
        }
        headers = {"accept": "application/json", "content-type": "application/json", "api-key": BREVO_API_KEY}
        resp = requests.post(brevo_url, headers=headers, json=payload, timeout=15)
        if resp.status_code in (200, 201):
            logging.info(f"Brevo alert sent to {ALERT_EMAIL}")
            return True
        else:
            logging.error(f"Brevo send failed: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        logging.error(f"Error sending Brevo email alert: {e}")
        return False

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard"))

# Email scan route (uses placeholder model if email_model not present)
@app.route("/scan-email", methods=["POST"])
def scan_email():
    subject = request.form.get("email_subject", "")
    body = request.form.get("email_body", "")
    # If you have an ML model loaded, use it. Otherwise return a safe placeholder.
    try:
        email_model = globals().get("email_model", None)
        if email_model and hasattr(email_model, "predict"):
            # Expect model.predict returns something meaningful — adapt as needed
            pred = email_model.predict([subject + " " + body])
            result = {"is_phishing": bool(pred[0]), "confidence": 90}
        else:
            # Placeholder result for now
            result = {"is_phishing": False, "confidence": 97}
    except Exception as e:
        logging.error(f"Error running email_model: {e}")
        result = {"is_phishing": False, "confidence": 0}

    return render_template("email_scanner.html", result=result)


@app.route("/dashboard")
def dashboard():
    try:
        # 1. Threats per day
        threats_per_day = (
            db.session.query(
                func.date(ThreatLog.timestamp),
                func.count(ThreatLog.id)
            )
            .group_by(func.date(ThreatLog.timestamp))
            .order_by(func.date(ThreatLog.timestamp))
            .all()
        )

        daily_labels = [str(row[0]) for row in threats_per_day]
        daily_values = [row[1] for row in threats_per_day]

        # 2. Severity distribution
        severity_data = (
            db.session.query(ThreatLog.severity, func.count(ThreatLog.id))
            .group_by(ThreatLog.severity)
            .all()
        )

        severity_labels = [row[0] for row in severity_data]
        severity_values = [row[1] for row in severity_data]

        # 3. Category distribution
        category_data = (
            db.session.query(ThreatLog.category, func.count(ThreatLog.id))
            .group_by(ThreatLog.category)
            .all()
        )

        category_labels = [row[0] for row in category_data]
        category_values = [row[1] for row in category_data]

        # 4. STAT CARDS (REAL LIVE DATA)
        stats = {
            "emails_scanned": ThreatLog.query.filter_by(category="email").count(),
            "malicious_urls": ThreatLog.query.filter(
                (ThreatLog.category == "url_scan") &
                (ThreatLog.status == "malicious")
            ).count(),
            "qr_threats": ThreatLog.query.filter_by(category="qr").count(),
            "soc_events": ThreatLog.query.filter_by(category="soc").count(),
            "ti_queries": ThreatLog.query.filter_by(category="threat_lookup").count(),
            "active_alerts": ThreatLog.query.filter(
                ThreatLog.severity.in_(["High", "Critical"])
            ).count()
        }

        # 5. Recent logs
        logs_url   = ThreatLog.query.filter_by(category="url_scan").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_email = ThreatLog.query.filter_by(category="email").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_soc   = ThreatLog.query.filter_by(category="soc").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_qr    = ThreatLog.query.filter_by(category="qr").order_by(ThreatLog.timestamp.desc()).limit(10).all()

        return render_template(
            "dashboard.html",
            logs_url=logs_url,
            logs_email=logs_email,
            logs_soc=logs_soc,
            logs_qr=logs_qr,
            daily_labels=daily_labels,
            daily_values=daily_values,
            severity_labels=severity_labels,
            severity_values=severity_values,
            category_labels=category_labels,
            category_values=category_values,
            stats=stats,      # <-- added
            active_page="dashboard"
        )

    except Exception as e:
        print("ERROR:", e)
        return render_template("dashboard.html")

@app.route("/qr_detector", methods=["GET"])
def qr_detector():
    return render_template("qr_detector.html")

@app.route("/system-health")
def system_health():
    return render_template("system_health.html")

@app.route("/reports")
def reports():
    return render_template("reports.html")

@app.route("/logs")
def logs():

    logs_tabs = ThreatLog.query.filter_by(category="tabs").order_by(ThreatLog.timestamp.desc()).all()
    logs_url  = ThreatLog.query.filter_by(category="url_scan").order_by(ThreatLog.timestamp.desc()).all()
    logs_email = ThreatLog.query.filter_by(category="email").order_by(ThreatLog.timestamp.desc()).all()
    logs_soc = ThreatLog.query.filter_by(category="soc").order_by(ThreatLog.timestamp.desc()).all()
    logs_qr = ThreatLog.query.filter_by(category="qr").order_by(ThreatLog.timestamp.desc()).all()

    return render_template(
        "logs.html",
        logs_tabs=logs_tabs,
        logs_url=logs_url,
        logs_email=logs_email,
        logs_soc=logs_soc,
        logs_qr=logs_qr,
        active_page="logs"
    )


@app.route("/api/clear-logs", methods=["POST"])
@limiter.limit("5 per minute")
def clear_logs():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    category = (data.get("category") or "").strip()  # Optional: url_scan, email, soc, qr

    if username != "admin" or password != "admin123":
        return jsonify({"error": "Unauthorized"}), 401

    try:
        if category:
            # Clear specific category
            deleted = ThreatLog.query.filter_by(category=category).delete()
        else:
            # Clear all
            deleted = ThreatLog.query.delete()
        db.session.commit()
        return jsonify({"ok": True, "deleted": deleted, "category": category or "all"})
    except Exception as e:
        db.session.rollback()
        logging.error(f"clear_logs error: {e}")
        return jsonify({"error": "Failed to clear logs"}), 500

# Play alert sound (safe)
def play_alert_sound():
    global last_alert_time
    current_time = time.time()
    if current_time - last_alert_time < 5:
        return
    last_alert_time = current_time

    if not _pygame_ok:
        logging.info("Skipping sound — pygame not available")
        return

    def sound():
        try:
            pygame.mixer.music.load("alert_sound.mp3")
            pygame.mixer.music.play()
            pygame.time.delay(4000)
            pygame.mixer.music.stop()
        except Exception as e:
            logging.error(f"play_alert_sound error: {e}")

    threading.Thread(target=sound, daemon=True).start()

# API - Fetch Threat Logs
@app.route("/api/threat_logs")
@limiter.limit("10 per second")
def get_threat_logs():
    logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
    return jsonify([
        {
            "timestamp": log.timestamp,
            "url": log.url,
            "status": log.status,
            "flagged_reason": log.flagged_reason,
            "severity": log.severity
        }
        for log in logs
    ])


@app.route("/threat_lookup")
def threat_lookup():
    return render_template("threat_lookup.html")


@app.route("/api/get_settings", methods=["GET"])
def api_get_settings():
    return jsonify(load_settings())


@app.route("/api/update_settings", methods=["POST"])
def api_update_settings():
    try:
        data = request.get_json() or {}
        # Basic validation and normalization
        cleaned = {
            "email_alerts": (data.get("email_alerts") or DEFAULT_SETTINGS["email_alerts"]).lower(),
            "notification_frequency": (data.get("notification_frequency") or DEFAULT_SETTINGS["notification_frequency"]).lower(),
            "virustotal_api_key": data.get("virustotal_api_key") or "",
            "auto_scan": bool(data.get("auto_scan", DEFAULT_SETTINGS["auto_scan"])),
            "log_retention": str(data.get("log_retention") or DEFAULT_SETTINGS["log_retention"]),
        }
        settings = save_settings(cleaned)
        return jsonify({"success": True, "message": "Settings updated", "settings": settings})
    except Exception as e:
        logging.error(f"api_update_settings error: {e}")
        return jsonify({"success": False, "error": "Failed to save settings"}), 500


@app.route("/api/test_virustotal", methods=["POST"])
def api_test_virustotal():
    data = request.get_json() or {}
    api_key = data.get("api_key") or load_settings().get("virustotal_api_key")
    if not api_key:
        return jsonify({"success": False, "error": "API key required"}), 400

    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code == 200:
            return jsonify({"success": True})
        if resp.status_code == 401:
            return jsonify({"success": False, "error": "Unauthorized API key"}), 401
        return jsonify({"success": False, "error": f"VT error {resp.status_code}"}), resp.status_code
    except Exception as e:
        logging.error(f"api_test_virustotal error: {e}")
        return jsonify({"success": False, "error": "Connection error"}), 500

@app.route("/api/threat_trends")
def get_threat_trends():
    try:
        data = (
            db.session.query(
                func.date(ThreatLog.timestamp).label("date"),
                func.count().label("count")
            )
            .group_by(func.date(ThreatLog.timestamp))
            .order_by(func.date(ThreatLog.timestamp).desc())
            .all()
        )
        trends_dict = {str(row.date): row.count for row in data}
        return jsonify(trends_dict)
    except Exception as e:
        logging.error(f"Error fetching threat trends: {e}")
        return jsonify({"error": "Failed to fetch threat trends"}), 500

@app.route('/threat-trends')
def threat_trends():
    return jsonify({"message": "Threat Trends Data"})

@app.route('/threat-distribution')
def threat_distribution():
    return jsonify({"message": "Threat Distribution Data"})

@app.route('/threat-statistics')
def threat_statistics():
    return jsonify({"message": "Threat Statistics Data"})

# Tab activity ingestion (from browser extension)
@app.route("/api/tab-activity", methods=["POST"])
def tab_activity():
    try:
        data = request.get_json() or {}
        url = (data.get("url") or "").strip()
        title = data.get("title") or ""
        action = data.get("action") or "switch"
        if not url:
            return jsonify({"error": "url required"}), 400

        entry = ThreatLog(
            category="tabs",
            url=url,
            status="INFO",
            severity="Low",
            flagged_reason=f"Tab {action}: {title}".strip()
        )
        db.session.add(entry)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception as e:
        logging.error(f"tab_activity error: {e}")
        db.session.rollback()
        return jsonify({"error": "failed"}), 500

@app.route("/api/threat_lookup", methods=["POST"])
@limiter.limit("5 per second")
def threat_lookup_api():
    data = request.get_json() or {}
    url = data.get("query") or data.get("url") or ""
    force_refresh = bool(data.get("force_refresh", False))
    if not url:
        return jsonify({"error": "URL is required"}), 400
    try:
        ti = unified_check_url(url, force_refresh=force_refresh, include_ip_enrichment=False)
        return jsonify({
            "status": ti.get("final_status", "Unknown"),
            "severity": ti.get("severity", "Unknown"),
            "detected_by": ti.get("detected_by"),
            "sources": ti.get("sources", {}),
            "cache": ti.get("cache", {}),
            "ai": ti.get("ai", {}),
        })
    except Exception as e:
        logging.error(f"Error during threat lookup: {e}")
        return jsonify({"error": "Error during threat lookup"}), 500

@app.route("/settings")
def settings():
    current_settings = load_settings()
    return render_template("settings.html", virustotal_api_key=current_settings.get("virustotal_api_key", ""))

@app.route("/check-url", methods=["POST"])
@limiter.limit("5 per second")
def check_url():
    data = request.get_json() or {}
    url = data.get("url")
    force_refresh = bool(data.get("force_refresh", False))
    include_ip_enrichment = bool(data.get("include_ip_enrichment") or data.get("include_ip") or False)
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        # Default to fast path (skip IP/RDAP) unless explicitly requested
        ti = unified_check_url(
            url,
            force_refresh=force_refresh,
            include_ip_enrichment=include_ip_enrichment,
        )

        # ---- SAVE TO ThreatLog (SQLAlchemy) ----
        entry = ThreatLog(
            category="url_scan",
            url=url,
            flagged_reason=f"{ti.get('detected_by') or 'TI Pipeline'} ({ti.get('final_status')})",
            severity=ti.get("severity", "Unknown"),
            status=ti.get("final_status", "Unknown"),
            details=json.dumps({
                "sources": ti.get("sources", {}),
                "ai": ti.get("ai", {}),
                "cache": ti.get("cache", {})
            })
        )
        db.session.add(entry)
        db.session.commit()

        # If malicious -> send alert
        if ti.get("final_status") in ("Malicious", "Phishing"):
            send_brevo_email(client_ip, url, ti.get("final_status"), ti.get("severity"))
            play_alert_sound()

        return jsonify({
            "status": ti.get("final_status", "Unknown"),
            "severity": ti.get("severity", "Unknown"),
            "detected_by": ti.get("detected_by"),
            "sources": ti.get("sources", {}),
            "cache": ti.get("cache", {}),
            "ai": ti.get("ai", {}),
        })

    except Exception as e:
        logging.error(f"Error during URL check: {e}")
        return jsonify({"error": "Error checking URL"}), 500


# Real-time threat logs via websocket (background emitter)


def generate_threat_logs():
    while True:
        time.sleep(5)
        try:
            with app.app_context():
                latest = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).first()
                if latest:
                    socketio.emit(
                        "threat_log",
                        {
                            "message": "New Threat Detected!",
                            "threat": {
                                "id": latest.id,
                                "timestamp": latest.timestamp.isoformat(),
                                "category": latest.category,
                                "url": latest.url,
                                "status": latest.status,
                                "flagged_reason": latest.flagged_reason,
                                "severity": latest.severity,
                                "details": latest.details,
                            },
                        }
                    )
        except Exception as e:
            logging.error(f"generate_threat_logs error: {e}")

threading.Thread(target=generate_threat_logs, daemon=True).start()


# Download Threat Logs CSV
@app.route("/download-threat-log")
def download_threat_log():
    try:
        log_file = "threat_logs.csv"
        logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
        with open(log_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Timestamp", "URL", "Status", "Flagged Reason", "Severity"])
            for log in logs:
                writer.writerow([log.id, log.timestamp, log.url, log.status, log.flagged_reason, log.severity])
        return send_file(log_file, as_attachment=True, mimetype='text/csv')
    except Exception as e:
        logging.error(f"Error generating threat log CSV: {e}")
        return jsonify({"error": "Failed to generate threat log CSV"}), 500



# ---------------------------
# QR Code Generator (For Testing QRishing)
# ---------------------------
@app.route("/api/generate-qr", methods=["POST"])
@limiter.limit("10/minute")
def generate_qr():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        url = data["url"].strip()
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400

        # Generate QR code in memory
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Save to a BytesIO buffer
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="image/png",
            download_name="qrcode.png"
        )

    except Exception as e:
        logging.error(f"QR generation error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/soc-analyzer", methods=["GET", "POST"])
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

        # ---- SAVE TO DATABASE ----
        log_entry = ThreatLog(
            category="soc",
            url="SOC Analysis",
            flagged_reason=result.get("ai_analysis", {}).get("summary", "SOC analysis completed"),
            severity=result.get("ai_analysis", {}).get("severity", "Low")
        )
        db.session.add(log_entry)
        db.session.commit()

        return jsonify(result)

    return render_template("soc_analyzer.html", active_page="soc-analyzer")




# ---------------------------
# QRishing Detection API (SQLAlchemy)
# ---------------------------
@app.route("/api/scan-qr", methods=["POST"])
@limiter.limit("5 per second")
def scan_qr():
    try:
        if "qr_image" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["qr_image"]
        if file.filename == "":
            return jsonify({"error": "Empty file"}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        img = cv2.imread(filepath)
        if img is None:
            return jsonify({"error": "Invalid image"}), 400

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        if not data:
            return jsonify({"error": "No QR code detected"}), 400

        qr_content = data.strip()

        # Only treat QR content as URL if it begins with HTTP/S
        urls = [qr_content] if qr_content.startswith(("http://", "https://")) else []
        results = {}

        for url in urls:
            try:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}

                # Submit to VirusTotal
                submit_resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=20
                )

                if submit_resp.status_code not in (200, 201):
                    results[url] = "VirusTotal submit failed"
                    continue

                analysis_id = submit_resp.json().get("data", {}).get("id")

                # Fetch analysis result
                analysis_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=20
                )

                stats = analysis_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)

                # Determine status & severity
                status = (
                    "Malicious" if malicious_count > 0 else
                    "Suspicious" if suspicious_count > 0 else
                    "Safe"
                )
                severity = (
                    "High" if status == "Malicious" else
                    "Medium" if status == "Suspicious" else
                    "Low"
                )

                results[url] = status

                # ---------------------------------------------------
                # 🚀 SAVE TO ThreatLog (SQLAlchemy)
                # ---------------------------------------------------
                entry = ThreatLog(
                    category="qr",
                    url=url,
                    status=status,
                    flagged_reason="QRishing Scan",
                    severity=severity,
                    details=json.dumps({
                        "malicious_count": malicious_count,
                        "suspicious_count": suspicious_count,
                        "vt_analysis_id": analysis_id
                    })
                )
                db.session.add(entry)
                db.session.commit()
                # ---------------------------------------------------

                # Alert & email on malicious QR
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

                if status == "Malicious":
                    send_brevo_email(client_ip, url, status, severity)
                    play_alert_sound()

            except Exception as e:
                results[url] = f"Error: {str(e)}"

        return jsonify({
            "qr_content": qr_content,
            "urls_found": urls,
            "results": results
        })

    except Exception as e:
        logging.error(f"QR scan error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        schedule_auto_scan()  # Start auto-scan scheduler
    socketio.run(app, host="0.0.0.0", port=5000, debug=DEBUG_MODE)