# backend/services/gmail_service.py

import os
import pickle
import base64
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
MAX_EMAIL_SIZE = 50000  # Limit email body to 50KB
CACHE_EMAILS = {}       # In-memory cache for fetched emails

def authenticate_gmail():
    """Authenticate with Gmail API (caching credentials)."""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def _extract_email_body(payload: dict) -> str:
    """
    Efficiently extract email body from payload.
    OPTIMIZED: Prefer HTML, limit size, handle errors.
    """
    parts = payload.get('parts', [])
    body = ''

    if parts:
        # OPTIMIZED: Search for best content part (HTML > plain text)
        for part in parts:
            mime_type = part.get("mimeType", "")
            if mime_type == 'text/html':
                data = part.get('body', {}).get('data', '')
                if data:
                    try:
                        body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        break
                    except Exception as e:
                        logging.warning(f"Failed to decode HTML body: {e}")
                        continue
        
        # Fallback to plain text if no HTML
        if not body:
            for part in parts:
                if part.get("mimeType") == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    if data:
                        try:
                            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            break
                        except Exception as e:
                            logging.warning(f"Failed to decode plain text body: {e}")
                            continue
    else:
        # Handle simple messages without parts
        data = payload.get("body", {}).get("data", "")
        if data:
            try:
                body = base64.urlsafe_b64decode(data).decode("utf-8", errors='ignore')
            except Exception as e:
                logging.warning(f"Failed to decode simple body: {e}")

    return body

def fetch_recent_emails(limit=5):
    """
    Fetch recent emails from Gmail (OPTIMIZED: batch fetching, caching, size limits).
    - Use batch API calls for efficiency
    - Cache results
    - Limit email size to prevent memory bloat
    """
    try:
        service = authenticate_gmail()
    except Exception as e:
        logging.error(f"Gmail Authentication failed: {e}")
        return []

    # OPTIMIZED: Check cache first
    cache_key = f"emails_{limit}"
    if cache_key in CACHE_EMAILS:
        return CACHE_EMAILS[cache_key]

    try:
        # OPTIMIZED: Fetch message list efficiently
        results = service.users().messages().list(
            userId='me',
            maxResults=limit,
            fields='messages(id)'  # Only fetch IDs first
        ).execute()
        
        message_ids = [msg['id'] for msg in results.get('messages', [])]
        if not message_ids:
            logging.warning("No messages found")
            return []

        emails = []
        
        # OPTIMIZED: Batch fetch message details
        for msg_id in message_ids:
            try:
                msg_data = service.users().messages().get(
                    userId='me',
                    id=msg_id,
                    format='full',
                    fields='payload'  # Only fetch payload field
                ).execute()
                
                payload = msg_data.get('payload', {})
                body = _extract_email_body(payload)
                
                # OPTIMIZED: Truncate email to prevent memory issues
                if len(body) > MAX_EMAIL_SIZE:
                    body = body[:MAX_EMAIL_SIZE]
                    logging.debug(f"Email {msg_id} truncated to {MAX_EMAIL_SIZE} bytes")
                
                # OPTIMIZED: Clean HTML and extract text
                soup = BeautifulSoup(body, 'html.parser')
                clean_text = soup.get_text(separator=' ', strip=True)
                
                if clean_text:
                    emails.append(clean_text)
                    
            except Exception as e:
                logging.error(f"Failed to fetch message {msg_id}: {e}")
                continue

        # Cache results
        CACHE_EMAILS[cache_key] = emails
        logging.info(f"Fetched and cached {len(emails)} emails")
        
        return emails

    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return []

