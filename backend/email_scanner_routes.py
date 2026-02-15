#\backend\email_scanner_routes.py

import logging
from flask import Blueprint, render_template, request, jsonify
from backend.email_scanner import scan_emails  # scanning function

email_scanner = Blueprint("email_scanner", __name__, url_prefix="/email_scanner")

# Page route
@email_scanner.route("/", methods=["GET"])
def email_scanner_page():
    try:
        return render_template("email_scanner.html")
    except Exception as e:
        logging.error(f"Error loading email scanner page: {e}")
        return jsonify({"error": "Failed to load email scanner page"}), 500


# Form POST route (HTML form target)
@email_scanner.route("/fetch", methods=["POST"])
def fetch_emails():
    try:
        count = int(request.form.get("count", 5))
        emails = scan_emails(limit=count)
        return render_template("email_scanner.html", emails=emails)
    except ValueError:
        logging.error("Invalid count parameter")
        return jsonify({"error": "Invalid count parameter"}), 400
    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return jsonify({"error": f"Failed to fetch emails: {str(e)}"}), 500

# API route for AJAX or programmatic access
@email_scanner.route("/api/scan", methods=["POST"])
def scan_emails_api():
    try:
        data = request.get_json() or {}
        count = int(data.get("count", 5))
        
        if count < 1 or count > 50:
            return jsonify({"error": "Count must be between 1 and 50"}), 400
        
        emails = scan_emails(limit=count)
        return jsonify({
            "status": "success",
            "count": len(emails),
            "emails": emails
        })
    except ValueError:
        logging.error("Invalid count parameter")
        return jsonify({"error": "Invalid count parameter"}), 400
    except Exception as e:
        logging.error(f"Error in email scan API: {e}")
        return jsonify({"error": f"Failed to scan emails: {str(e)}"}), 500
