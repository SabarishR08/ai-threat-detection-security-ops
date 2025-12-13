# Threat Detection Platform

A Flask-based threat detection and monitoring stack that scans URLs, emails, and QR codes using layered threat intelligence (VirusTotal, Google Safe Browsing, PhishTank, AbuseIPDB, RDAP) and AI assistance (Gemini). It surfaces results in a real-time dashboard with alerts, logging, and a browser extension hook.

> **📚 Quick Links**: [Project Structure](PROJECT_STRUCTURE.md) | [Testing Guide](backend/tests/README.md) | [Contributing](CONTRIBUTING.md) | [Quick Reference](QUICK_REFERENCE.md) | [Documentation Index](docs/README.md)

## Features
- URL intelligence: unified pipeline with VT cache, GSB, PhishTank, AbuseIPDB, RDAP, and Gemini fusion scoring.
- Email scanning: Gmail fetch → URL checks → NLP classification → Brevo alerts and dashboard logging.
- QR/QRishing checks: decode QR images, submit to VT, log and alert on malicious detections.
- SOC log analysis: rule-based + Gemini REST analysis with structured JSON output.
- Dashboard + SocketIO: live threat cards, recent logs, CSV export, and settings page.
- Browser extension ingest: tab activity endpoint for capturing risky browsing events.

## Quickstart (local)
1) Install Python 3.11+ and create a venv:
   ```bash
   cd backend
   python -m venv .venv
   .venv\Scripts\activate  # on Windows
   pip install -r requirements.txt
   ```
2) Copy `.env.example` to `.env` and fill keys (VirusTotal, Safe Browsing, Gemini, Brevo, etc.).
3) Place Gmail OAuth creds at `backend/credentials/credentials.json` (for email scanning). The first run will create `token.pickle`.
4) Run the server (uses SocketIO):
   ```bash
   cd backend
   python app.py
   ```
5) Open http://localhost:5000/dashboard.

## Core endpoints
- POST `/check-url` — body `{ "url": "https://example.com", "force_refresh": false }`; returns unified verdict + AI reasoning and logs to DB.
- POST `/api/threat_lookup` — lighter lookup variant for UI forms.
- POST `/email_scanner/api/scan` — trigger Gmail fetch and analysis (limit via `count`).
- POST `/api/scan-qr` — multipart with `qr_image` to scan QR codes.
- POST `/api/tab-activity` — submit browser extension tab events for tracking.

## Architecture
See docs/architecture/diagram.md for the system flow (clients → Flask → threat intel/AI → SQLite/logs).

## Demo script (10 min)
- Dashboard: show live stats and recent threats.
- URL scan: submit a known phishing test URL; show verdict + log entry.
- Email scan: trigger `/email_scanner/api/scan` (limit small) and show classified result.
- QR scan: upload a test QR containing a benign URL; show scan result.
- SOC analyzer: paste a log snippet with failed SSH attempts; show JSON summary.

## Deployment notes
- SQLite path: backend/database/threats.db (auto-created). Override with `DATABASE_URL` if needed.
- Rate limits: Flask-Limiter guards key endpoints; adjust in backend/extensions.py.
- Alerts: Brevo email requires `BREVO_API_KEY`, `ALERT_EMAIL`, `SENDER_EMAIL`.

## Repo map
- backend/app.py — Flask app, routes, SocketIO, settings.
- backend/services/ — threat intel (virustotal, safebrowsing, phishtank, abuseipdb, rdap), AI fusion (gemini), email/Gmail helpers.
- backend/email_scanner.py — Gmail fetch + URL checks + NLP + alerts.
- backend/soc_analyzer.py — log AI analysis.
- backend/models.py — SQLAlchemy models (ThreatLog, Alert, BlacklistedIP).
- dashboard/ — templates and static assets for UI.
- docs/architecture/diagram.md — mermaid architecture diagram.

## Testing
Lightweight smoke: hit `/api/threat_lookup` with a safe URL and confirm 200 + `final_status` field. Full test suite is not bundled; prioritize manual endpoint checks with valid API keys.
