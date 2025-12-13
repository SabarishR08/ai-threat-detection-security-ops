#\backend\email_scanner_routes.py


from flask import Blueprint, render_template, request, jsonify
from email_scanner import scan_emails  # your scanning function

email_scanner = Blueprint("email_scanner", __name__, url_prefix="/email_scanner")

# Page route
@email_scanner.route("/", methods=["GET"])
def email_scanner_page():
    return render_template("email_scanner.html")


# Form POST route (HTML form target)
@email_scanner.route("/fetch", methods=["POST"])
def fetch_emails():
    count = int(request.form.get("count", 5))
    emails = scan_emails(limit=count)
    return render_template("email_scanner.html", emails=emails)

# API route for AJAX or programmatic access
@email_scanner.route("/api/scan", methods=["POST"])
def scan_emails_api():
    count = int(request.json.get("count", 5))
    emails = scan_emails(limit=count)
    return jsonify(emails)
