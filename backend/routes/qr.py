"""
QR Code Routes - QR code generation and QRishing detection
CRITICAL FIX: Uses unified pipeline instead of direct VirusTotal calls
"""
import os
import json
import base64
import logging
import cv2
import qrcode
from io import BytesIO
from flask import Blueprint, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from backend.extensions import limiter, db
from backend.models import ThreatLog
from backend.services.threat_lookup_service import unified_check_url
from backend.alerts.email_alerts_service import send_brevo_email_async
from backend.alerts.sound_alerts import play_alert_sound
from backend.utils.helpers import get_client_ip

qr_bp = Blueprint("qr", __name__)

@qr_bp.route("/qr_detector", methods=["GET"])
def qr_detector():
    return render_template("qr_detector.html")


@qr_bp.route("/api/generate-qr", methods=["POST"])
@limiter.limit("10/minute")
def generate_qr():
    """Generate QR code for testing QRishing"""
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        url = data["url"].strip()
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400

        # Generate QR code in memory (no disk writes)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Save to BytesIO buffer (memory only)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Return base64-encoded PNG inside JSON so the frontend can display it
        encoded = base64.b64encode(buffer.getvalue()).decode('ascii')
        return jsonify({
            "qr_code": encoded,
            "payload": url
        })

    except Exception as e:
        logging.error(f"QR generation error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@qr_bp.route("/api/scan-qr", methods=["POST"])
@limiter.limit("5 per second")
def scan_qr():
    """
    QRishing Detection API
    CRITICAL FIX: Uses unified_check_url pipeline instead of direct VT calls
    This ensures consistency with:
    - Risk scoring
    - Gemini explanation
    - Caching
    - Alert logic
    """
    try:
        if "qr_image" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["qr_image"]
        if file.filename == "":
            return jsonify({"error": "Empty file"}), 400

        # Use upload folder from app config
        upload_folder = os.environ.get("UPLOAD_FOLDER", "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)

        # Decode QR code
        img = cv2.imread(filepath)
        if img is None:
            return jsonify({"error": "Invalid image"}), 400

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        
        if not data:
            return jsonify({"error": "No QR code detected"}), 400

        qr_content = data.strip()

        # Extract URLs from QR content
        urls = [qr_content] if qr_content.startswith(("http://", "https://")) else []
        results = {}
        client_ip = get_client_ip(request)

        # CRITICAL FIX: Use unified pipeline for consistency
        for url in urls:
            try:
                # Use unified check - includes all threat intel sources
                ti = unified_check_url(
                    url,
                    force_refresh=False,
                    include_ip_enrichment=True  # Include IP/RDAP for QR threats
                )
                
                status = ti.get("final_status", "Unknown")
                severity = ti.get("severity", "Unknown")
                
                results[url] = status

                # Save to ThreatLog
                entry = ThreatLog(
                    category="qr",
                    url=url,
                    status=status,
                    flagged_reason=f"QRishing Scan - {ti.get('detected_by', 'Unknown')}",
                    severity=severity,
                    details=json.dumps({
                        "sources": ti.get("sources", {}),
                        "ai": ti.get("ai", {}),
                        "qr_content": qr_content
                    })
                )
                db.session.add(entry)
                db.session.commit()

                # Non-blocking alerts for malicious QR codes
                if status in ("Malicious", "Phishing"):
                    send_brevo_email_async(client_ip, url, status, severity)
                    play_alert_sound()

            except Exception as e:
                logging.error(f"QR URL check error for {url}: {e}")
                results[url] = f"Error: {str(e)}"

        return jsonify({
            "qr_content": qr_content,
            "urls_found": urls,
            "results": results
        })

    except Exception as e:
        logging.error(f"QR scan error: {e}")
        return jsonify({"error": "Internal server error"}), 500
