"""
Email Routes - Email scanning and management
"""
import logging
from flask import Blueprint, render_template, request, jsonify
from backend.email_scanner import scan_emails

email_bp = Blueprint("email", __name__)

@email_bp.route("/scan-email", methods=["POST"])
def scan_email():
    """Email phishing detection endpoint"""
    subject = request.form.get("email_subject", "")
    body = request.form.get("email_body", "")
    
    try:
        # Check if ML model exists
        email_model = globals().get("email_model", None)
        if email_model and hasattr(email_model, "predict"):
            pred = email_model.predict([subject + " " + body])
            result = {"is_phishing": bool(pred[0]), "confidence": 90}
        else:
            # Use email scanner service
            result = scan_emails(subject, body)
    except Exception as e:
        logging.error(f"Error running email scan: {e}")
        result = {"is_phishing": False, "confidence": 0}

    return render_template("email_scanner.html", result=result)
