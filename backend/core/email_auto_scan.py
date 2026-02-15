"""
Auto-scan polling for Gmail using credentials.json.
Polls for new emails periodically and runs them through the analysis pipeline.
Emits Socket.IO events for UI updates.
"""
import os
import json
import logging
import base64
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Last processed message ID (persisted locally)
LAST_SCAN_FILE = os.path.join(os.path.dirname(__file__), "..", "instance", "last_email_scan.json")
os.makedirs(os.path.dirname(LAST_SCAN_FILE), exist_ok=True)

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def load_credentials():
    """Load Gmail credentials from credentials.json."""
    creds_path = os.path.join(os.path.dirname(__file__), "..", "credentials", "credentials.json")
    if not os.path.exists(creds_path):
        logging.warning(f"credentials.json not found at {creds_path}")
        return None
    
    try:
        creds = Credentials.from_authorized_user_file(creds_path, GMAIL_SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
        return creds
    except Exception as e:
        logging.error(f"Failed to load Gmail credentials: {e}")
        return None


def get_last_scan_id():
    """Get the last processed message ID."""
    try:
        if os.path.exists(LAST_SCAN_FILE):
            with open(LAST_SCAN_FILE, "r") as f:
                data = json.load(f)
                return data.get("last_message_id")
    except Exception as e:
        logging.error(f"Error reading last_scan_id: {e}")
    return None


def save_last_scan_id(message_id):
    """Save the last processed message ID."""
    try:
        data = {"last_message_id": message_id, "timestamp": datetime.utcnow().isoformat()}
        with open(LAST_SCAN_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving last_scan_id: {e}")


def fetch_new_emails(service, max_results=5):
    """
    Fetch recent unread emails from Gmail.
    Returns list of email dicts with id, headers, and body.
    """
    if not service:
        return []
    
    try:
        # Fetch unread emails from the inbox
        results = service.users().messages().list(
            userId="me",
            q="is:unread",
            maxResults=max_results
        ).execute()
        
        messages = results.get("messages", [])
        if not messages:
            logging.info("No unread emails found.")
            return []
        
        emails = []
        for msg in messages:
            try:
                msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
                headers = msg_data["payload"]["headers"]
                
                # Extract subject, from, to
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
                from_addr = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
                to_addr = next((h["value"] for h in headers if h["name"] == "To"), "Unknown")
                
                # Extract body (simplified)
                body = ""
                if "parts" in msg_data["payload"]:
                    for part in msg_data["payload"]["parts"]:
                        if part["mimeType"] == "text/plain":
                            if "data" in part["body"]:
                                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
                                break
                elif "body" in msg_data["payload"]:
                    if "data" in msg_data["payload"]["body"]:
                        body = base64.urlsafe_b64decode(msg_data["payload"]["body"]["data"]).decode("utf-8", errors="ignore")
                
                emails.append({
                    "id": msg["id"],
                    "subject": subject,
                    "from": from_addr,
                    "to": to_addr,
                    "body": body[:500],  # Limit body for processing
                    "timestamp": datetime.utcnow().isoformat()
                })
            except HttpError as e:
                logging.error(f"Error fetching message {msg['id']}: {e}")
                continue
        
        return emails
    
    except HttpError as e:
        logging.error(f"Gmail API error: {e}")
        return []
    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return []


def run_auto_scan(app_context, socketio, email_analyzer_func):
    """
    Polling job: fetch new emails and run through analysis pipeline.
    Emits Socket.IO events for UI updates.
    """
    try:
        creds = load_credentials()
        if not creds:
            logging.warning("Gmail credentials not available; skipping auto-scan.")
            return
        
        service = build("gmail", "v1", credentials=creds)
        emails = fetch_new_emails(service, max_results=5)
        
        if not emails:
            logging.info("No new emails to scan.")
            return
        
        logging.info(f"Auto-scan found {len(emails)} new emails.")
        
        # Emit start event
        socketio.emit("auto_scan_started", {"count": len(emails)})
        
        processed = 0
        threats_found = 0
        
        for email in emails:
            try:
                # Run through analysis pipeline
                result = email_analyzer_func(
                    subject=email["subject"],
                    body=email["body"],
                    from_addr=email["from"],
                    auto_scan=True
                )
                
                if result.get("is_phishing") or result.get("severity") in ("High", "Critical"):
                    threats_found += 1
                
                processed += 1
                
                # Optional: emit per-email update
                socketio.emit("email_auto_scanned", {
                    "subject": email["subject"],
                    "from": email["from"],
                    "result": result
                })
                
            except Exception as e:
                logging.error(f"Error analyzing email {email['subject']}: {e}")
                continue
        
        # Emit completion event
        socketio.emit("auto_scan_completed", {
            "processed": processed,
            "threats_found": threats_found
        })
        
        # Update last scan ID
        if emails:
            save_last_scan_id(emails[0]["id"])
        
        logging.info(f"Auto-scan completed: {processed} processed, {threats_found} threats found.")
    
    except Exception as e:
        logging.error(f"Error in run_auto_scan: {e}")
        socketio.emit("auto_scan_failed", {"error": str(e)})
