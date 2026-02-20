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
    """Generate QR code for various payload types"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request data is required"}), 400

        payload_type = data.get("type", "url")
        qr_content = ""
        
        # Build QR content based on payload type
        if payload_type == "url":
            url = data.get("url", "").strip()
            if not url:
                return jsonify({"error": "URL is required"}), 400
            qr_content = url
            
        elif payload_type == "wifi":
            ssid = data.get("ssid", "").strip()
            if not ssid:
                return jsonify({"error": "WiFi SSID is required"}), 400
            security = data.get("security", "WPA")
            password = data.get("password", "").strip()
            # WiFi QR format: WIFI:T:WPA;S:MySSID;P:MyPassword;;
            qr_content = f"WIFI:T:{security};S:{ssid};P:{password};;"
            
        elif payload_type == "sms":
            phone = data.get("phone", "").strip()
            message = data.get("message", "").strip()
            if not phone:
                return jsonify({"error": "Phone number is required"}), 400
            # SMS QR format: smsto:+1234567890:Message text
            qr_content = f"smsto:{phone}:{message}"
            
        elif payload_type == "tel":
            phone = data.get("phone", "").strip()
            if not phone:
                return jsonify({"error": "Phone number is required"}), 400
            # Tel QR format: tel:+1234567890
            qr_content = f"tel:{phone}"
            
        elif payload_type == "email":
            email = data.get("email", "").strip()
            if not email:
                return jsonify({"error": "Email address is required"}), 400
            subject = data.get("subject", "").strip()
            body = data.get("body", "").strip()
            # Email QR format: mailto:user@example.com?subject=Subject&body=Body
            qr_content = f"mailto:{email}"
            params = []
            if subject:
                params.append(f"subject={subject}")
            if body:
                params.append(f"body={body}")
            if params:
                qr_content += "?" + "&".join(params)
                
        elif payload_type == "upi":
            upi_id = data.get("upi_id", "").strip()
            if not upi_id:
                return jsonify({"error": "UPI ID is required"}), 400
            amount = data.get("amount", "").strip()
            description = data.get("description", "").strip()
            # UPI QR format: upi://pay?pa=user@bank&am=100&tn=Description
            qr_content = f"upi://pay?pa={upi_id}"
            if amount:
                qr_content += f"&am={amount}"
            if description:
                qr_content += f"&tn={description}"
                
        elif payload_type == "text":
            text = data.get("text", "").strip()
            if not text:
                return jsonify({"error": "Text content is required"}), 400
            qr_content = text
            
        else:
            return jsonify({"error": f"Unsupported payload type: {payload_type}"}), 400

        if not qr_content:
            return jsonify({"error": "QR content cannot be empty"}), 400

        # Generate QR code in memory (no disk writes)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(qr_content)
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
            "payload": qr_content
        })

    except Exception as e:
        logging.error(f"QR generation error: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


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
