# \backend\email_scanner.py

import asyncio
import logging
from datetime import datetime
from models import db, ThreatLog
from services.gmail_service import fetch_recent_emails
from services.virustotal_service import check_urls_async
from services.google_safebrowsing_service import check_urls_safebrowsing_async
from services.alert_service import send_brevo_alert
from utils.url_utils import extract_urls
from utils.helpers import invalidate_dashboard_cache
from services.gemini_service import classify_email_nlp
from extensions import socketio
import nest_asyncio

# Apply nest_asyncio to fix "event loop already running" in Flask
nest_asyncio.apply()

SNIPPET_LENGTH = 250
MAX_EMAIL_LENGTH = 10000  # Limit email analysis to first 10k chars (prevent memory spike)
MIN_URL_THRESHOLD = 3     # If more than 3 URLs, likely spam, skip detailed analysis
BATCH_SIZE = 5            # Process emails in batches to avoid memory overload
CACHE_CLASSIFIED = {}     # Simple cache for classified emails (in-memory)


async def safe_send_alert(subject: str, body: str):
    """Wrapper to safely run the sync send_brevo_alert in executor."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_brevo_alert, subject, body)


async def process_email(email_text: str, index: int):
    """
    Process a single email efficiently (OPTIMIZED for speed and memory).
    - Truncate email to max length (prevent memory bloat)
    - Extract and check URLs only if found
    - Batch NLP classification with caching
    - Efficient DB insertion
    """
    # OPTIMIZED: Truncate email to prevent memory issues with very long emails
    email_text = email_text[:MAX_EMAIL_LENGTH] if email_text else ""
    
    urls = extract_urls(email_text)
    flagged = []
    
    # OPTIMIZED: Skip detailed analysis if too many URLs (likely spam)
    if len(urls) > MIN_URL_THRESHOLD:
        logging.warning(f"Email {index} has {len(urls)} URLs, likely spam - skipping detailed analysis")
        return {
            "email_index": index,
            "content": email_text[:SNIPPET_LENGTH],
            "urls": {},
            "nlp_category": "Spam",
            "nlp_reason": "Too many URLs",
            "skipped": True
        }

    # OPTIMIZED: Only create tasks for actual work
    tasks = []
    
    if urls:
        # Only run URL checks if we have URLs
        tasks.append(check_urls_async(urls))
        tasks.append(check_urls_safebrowsing_async(urls))
    
    # Always run NLP classification (with caching)
    loop = asyncio.get_event_loop()
    email_hash = hash(email_text)  # Simple cache key
    if email_hash not in CACHE_CLASSIFIED:
        tasks.append(loop.run_in_executor(None, classify_email_nlp, email_text))
        run_nlp = True
    else:
        run_nlp = False

    # Fire all tasks in parallel
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        results = []

    # OPTIMIZED: Efficient result processing
    vt_results = {}
    sb_results = {}
    nlp_result = {"category": "Unknown", "reason": ""}
    
    if urls and len(results) >= 2:
        vt_results = results[0] if isinstance(results[0], dict) else {}
        sb_results_list = results[1] if isinstance(results[1], list) else []
        sb_results = {item["url"]: item["status"] for item in sb_results_list}
        
        # Get NLP result from cache or new result
        if run_nlp and len(results) > 2:
            nlp_result = results[2] if isinstance(results[2], dict) else {}
            CACHE_CLASSIFIED[email_hash] = nlp_result
        elif email_hash in CACHE_CLASSIFIED:
            nlp_result = CACHE_CLASSIFIED[email_hash]
    elif len(results) > 0:
        nlp_result = results[0] if isinstance(results[0], dict) else {}
        CACHE_CLASSIFIED[email_hash] = nlp_result

    # ---- Merge and flag URLs ----
    merged_urls = {}
    for url in urls:
        vt_status = vt_results.get(url, "Unknown")
        sb_status = sb_results.get(url, "Unknown")
        
        merged_urls[url] = {
            "virustotal": vt_status,
            "safebrowsing": sb_status
        }
        
        # Flag if threat detected
        if vt_status in ["Malicious", "Suspicious"] or sb_status not in ["Safe", "Unknown"]:
            flagged.append(f"{url} → VT:{vt_status} SB:{sb_status}")

    # ---- Batch DB insert (OPTIMIZED: use single commit) ----
    if merged_urls or flagged:
        log_entries = []
        for url, result in merged_urls.items():
            is_flagged = any(url in f for f in flagged)
            log_entries.append(ThreatLog(
                timestamp=datetime.now(),
                url=url,
                status=result["virustotal"],
                flagged_reason="Threat Detected" if is_flagged else "Safe",
                category='email',
                severity='High' if is_flagged else 'Low'
            ))
        
        if log_entries:
            try:
                db.session.add_all(log_entries)
                db.session.commit()
                invalidate_dashboard_cache()
                try:
                    socketio.emit("update_logs")
                except Exception as emit_err:
                    logging.debug(f"socket emit skipped: {emit_err}")
            except Exception as e:
                logging.error(f"Email {index} DB insert error: {e}")
                db.session.rollback()

    # If no URLs were found, still record the scan event for traceability
    if not merged_urls and not flagged:
        try:
            db.session.add(ThreatLog(
                timestamp=datetime.now(),
                url="(no url)",
                status="Safe",
                flagged_reason="No URLs found",
                category='email',
                severity='Low',
                details=email_text[:SNIPPET_LENGTH]
            ))
            db.session.commit()
            invalidate_dashboard_cache()
            try:
                socketio.emit("update_logs")
            except Exception as emit_err:
                logging.debug(f"socket emit skipped: {emit_err}")
        except Exception as e:
            logging.error(f"Email {index} no-URL log insert error: {e}")
            db.session.rollback()

    # ---- Send alert asynchronously if needed ----
    if flagged:
        body = (
            f"<b>Security Risk - Email {index}</b><br><br>"
            f"<b>Content:</b><br>{email_text[:SNIPPET_LENGTH]}...<br><br>"
            f"<b>Flagged URLs:</b><br>" + "<br>".join(flagged)
        )
        try:
            await safe_send_alert(f"🚨 Email Alert #{index}", body)
        except Exception as e:
            logging.warning(f"Alert send failed for email {index}: {e}")

    return {
        "email_index": index,
        "content": email_text[:SNIPPET_LENGTH],
        "urls": merged_urls,
        "nlp_category": nlp_result.get("category", "Unknown"),
        "nlp_reason": nlp_result.get("reason", ""),
        "flagged_count": len(flagged),
        "skipped": False
    }



async def scan_emails_async(limit: int = 5):
    """
    Scan multiple emails concurrently (OPTIMIZED: batch processing, early exit).
    - Fetch emails efficiently
    - Process in batches to avoid memory spike
    - Early exit on errors
    """
    try:
        emails = fetch_recent_emails(limit=limit)
        if not emails:
            logging.warning("No emails fetched from Gmail")
            return []
        
        # OPTIMIZED: Process in batches instead of all at once
        results = []
        for batch_start in range(0, len(emails), BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, len(emails))
            batch = emails[batch_start:batch_end]
            
            # Create tasks for this batch
            tasks = [
                process_email(email_text, i) 
                for i, email_text in enumerate(batch, start=batch_start + 1)
            ]
            
            # Process batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend([r for r in batch_results if not isinstance(r, Exception)])
            
            # Log progress
            logging.info(f"Processed batch {batch_start//BATCH_SIZE + 1}: {len(batch)} emails")
        
        logging.info(f"Total emails processed: {len(results)}")
        return results
        
    except Exception as e:
        logging.error(f"Email scan error: {e}")
        return []


def scan_emails(limit: int = 5):
    """Synchronous wrapper for Flask routes."""
    return asyncio.run(scan_emails_async(limit=limit))

