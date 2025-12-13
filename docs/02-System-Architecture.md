# 🏗️ SYSTEM ARCHITECTURE & DESIGN

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Dashboard | Email Scanner | Settings | QR Detector | SOC │  │
│  │ (Jinja2 Templates + Tailwind CSS + Chart.js)             │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────┬──────────────────────────────────────────────┬────┘
              │ HTTP/REST                         WebSocket │
              │                                    Socket.IO │
       ┌──────▼─────────────────────────────────────▼───────┐
       │              FLASK APPLICATION SERVER               │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ API Routes (Flask-RESTful)                     │ │
       │  │ • GET /api/get_settings                        │ │
       │  │ • POST /api/update_settings (CSRF-protected)  │ │
       │  │ • GET/POST /api/scan_email                    │ │
       │  │ • POST /api/lookup_url                        │ │
       │  │ • GET /api/get_csrf_token                     │ │
       │  └────────────────────────────────────────────────┘ │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ Security Layer                                 │ │
       │  │ • CSRF Token Validation (419 on fail)         │ │
       │  │ • Rate Limiting (5/min on /api/update_settings)│ │
       │  │ • Session Management (24h timeout)             │ │
       │  │ • Audit Logging (all changes)                  │ │
       │  │ • Secret Masking (API keys → **REDACTED**)    │ │
       │  └────────────────────────────────────────────────┘ │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ Core Business Logic                            │ │
       │  │ • email_scanner.py (ML + rule-based)          │ │
       │  │ • threat_checker.py (severity scoring)         │ │
       │  │ • soc_analyzer.py (log anomalies)             │ │
       │  │ • payload_detector.py (malicious content)      │ │
       │  │ • qr_detector.py (phishing QR codes)          │ │
       │  └────────────────────────────────────────────────┘ │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ Threat Intelligence Services                   │ │
       │  │ • virustotal_service.py ↔ VirusTotal API      │ │
       │  │ • gemini_service.py ↔ Google Gemini AI        │ │
       │  │ • abuseipdb_service.py ↔ AbuseIPDB            │ │
       │  │ • google_safebrowsing_service.py               │ │
       │  │ • phishtank_service.py                         │ │
       │  │ • threat_lookup_service.py (orchestration)     │ │
       │  └────────────────────────────────────────────────┘ │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ Background Jobs (APScheduler)                  │ │
       │  │ • auto_scan job (every 5 minutes)             │ │
       │  │ • cleanup_old_logs job (daily)                │ │
       │  │ • alert_flusher job (hourly/daily)            │ │
       │  └────────────────────────────────────────────────┘ │
       │  ┌────────────────────────────────────────────────┐ │
       │  │ Real-Time Events (Socket.IO)                   │ │
       │  │ • auto_scan_started                            │ │
       │  │ • email_auto_scanned                           │ │
       │  │ • auto_scan_completed                          │ │
       │  │ • auto_scan_failed                             │ │
       │  │ • alert_digest_flushed                         │ │
       │  │ • cleanup_old_logs_ran                         │ │
       │  └────────────────────────────────────────────────┘ │
       └──────┬──────────────────────────────────┬────────────┘
              │                                  │
     ┌────────▼─────────┐             ┌─────────▼────────────┐
     │  SQLite Database │             │   External APIs      │
     │  ┌────────────┐  │             │  ┌──────────────────┐│
     │  │ ThreatLog  │  │             │  │ VirusTotal       ││
     │  │ Alert      │  │             │  │ Google Gemini    ││
     │  │ AuditLog   │  │             │  │ AbuseIPDB        ││
     │  │ BlackList  │  │             │  │ PhishTank        ││
     │  │ User       │  │             │  │ Google Safe Brow.││
     │  │ Settings   │  │             │  │ Gmail API        ││
     │  └────────────┘  │             │  └──────────────────┘│
     └──────────────────┘             └──────────────────────┘
```

---

## Data Flow Diagrams

### 1. Manual Email Scan Flow

```
User clicks "Fetch & Analyze"
    ↓
Email Scanner Page → POST /api/scan_email
    ↓
email_scanner.py → Extract headers, body, URLs
    ↓
Parallel API Calls:
    ├→ virustotal_service.py (threat score)
    ├→ gemini_service.py (AI analysis)
    ├→ google_safebrowsing_service.py (phishing DB)
    └→ phishtank_service.py (known phishing URLs)
    ↓
threat_checker.py → Aggregate scores, determine severity
    ↓
Store in database (ThreatLog)
    ↓
Return results to frontend
    ↓
Email Scanner page updates table with "Manual" label
```

### 2. Auto-Scan Polling Flow (Every 5 Minutes)

```
APScheduler Job Trigger (5-minute interval)
    ↓
run_auto_scan() in backend/core/email_auto_scan.py
    ↓
Emit Socket.IO event: "auto_scan_started"
    ↓
load_credentials() → Get Gmail OAuth2 token
    ↓
fetch_new_emails() → Get unread emails from Gmail API
    ↓
For each email:
    ├→ Extract subject, from, body, URLs
    ├→ Call analyze_email_for_scan() (same pipeline as manual)
    ├→ Emit Socket.IO event: "email_auto_scanned"
    └→ Save to database (ThreatLog with auto_scan=True)
    ↓
save_last_scan_id() → Store highest email ID processed
    ↓
Emit Socket.IO event: "auto_scan_completed"
    ↓
Frontend (Email Scanner page):
    ├→ Receives events via Socket.IO
    ├→ Inserts new rows into results table
    └→ Shows notification: "X emails scanned, Y threats found"
```

### 3. Settings Update Flow (CSRF Protected)

```
User submits settings form
    ↓
Frontend JavaScript:
    ├→ Fetch /api/get_csrf_token (get token)
    └→ POST /api/update_settings with X-CSRF-Token header
    ↓
Backend (app.py):
    ├→ Validate CSRF token (compare with session)
    ├→ If invalid → Return 419 error
    └→ If valid → Continue
    ↓
Calculate changes:
    ├→ Compare old vs new settings
    ├→ Build per-field change log
    └→ Redact secrets (API keys → ***REDACTED***)
    ↓
Save to database:
    ├→ Update settings.json
    ├→ Insert AuditLog entry
    └→ Invalidate settings cache
    ↓
Emit Socket.IO event: "settings_updated"
    ↓
Return success to frontend
    ↓
Show snackbar notification: "Settings saved successfully"
```

---

## Component Details

### A. Email Scanner Module (`email_scanner.py`)

**Purpose**: Extract threat indicators from emails

**Key Functions**:
```python
def scan_emails(email_addresses, manual_override=False):
    """
    Main entry point for email scanning.
    Args:
        email_addresses: List of emails to scan
        manual_override: If False, use auto-scan logic
    Returns:
        {
            'emails_scanned': int,
            'threats_found': int,
            'results': [{ 'subject', 'from', 'threats', 'severity' }]
        }
    """
```

**Threat Detection**:
1. **URL Extraction** - Regex pattern matching
2. **VT Lookup** - Query VirusTotal for each URL
3. **ML Heuristics** - Gemini AI for phishing likelihood
4. **Payload Detection** - Check for known malicious patterns
5. **Severity Aggregation** - Combine scores (0-100)

---

### B. Settings Cache (`core/settings_cache.py`)

**Purpose**: Reduce database hits for frequently-accessed settings

**Logic**:
```
1. Check cache (in-memory dict)
2. If hit and not expired → Return cached value
3. If miss or expired → Load from database
4. Store in cache with TTL (60 seconds)
5. On settings update → Invalidate cache immediately
```

**Benefits**:
- ✅ 10x faster settings lookup
- ✅ Automatic expiration (prevents stale data)
- ✅ Explicit invalidation (consistency)

---

### C. Auto-Scan Polling (`core/email_auto_scan.py`)

**Purpose**: Automatically fetch and analyze Gmail emails every 5 minutes

**Key Components**:

```python
def load_credentials():
    """Load Gmail OAuth2 credentials, refresh if expired"""
    
def get_last_scan_id():
    """Get highest email ID already processed (prevent duplicates)"""
    
def save_last_scan_id(message_id):
    """Save highest email ID processed"""
    
def fetch_new_emails(service, max_results=5):
    """Query Gmail API for unread emails after last_scan_id"""
    
def run_auto_scan(app_context, socketio, email_analyzer_func):
    """Main job: fetch → analyze → emit events"""
```

**Flow**:
```python
# In app.py
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=lambda: run_auto_scan(app.app_context(), socketio, analyze_email_for_scan),
    trigger="interval",
    minutes=5
)
scheduler.start()
```

---

### D. Threat Lookup Service (`services/threat_lookup_service.py`)

**Purpose**: Orchestrate multi-API threat intelligence

**Supported Queries**:
- IP address → reputation, geolocation, abuse history
- Domain → WHOIS, SSL info, reputation
- URL → VirusTotal report, Safe Browsing status
- Email → Breach databases, reputation

**Parallel Execution**:
```python
def lookup_threat(indicator):
    """Query all APIs in parallel using threading"""
    results = {}
    threads = []
    
    # VT lookup
    t1 = Thread(target=lambda: results.update({
        'virustotal': virustotal_service.query(indicator)
    }))
    threads.append(t1)
    
    # AbuseIPDB lookup
    t2 = Thread(target=lambda: results.update({
        'abuseipdb': abuseipdb_service.query(indicator)
    }))
    threads.append(t2)
    
    # ... more APIs
    
    # Wait for all threads
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    return aggregate_results(results)
```

---

### E. Socket.IO Event Broadcasting

**Purpose**: Real-time frontend updates without page reload

**Events Emitted**:

| Event | Payload | When Emitted |
|-------|---------|--------------|
| `auto_scan_started` | `{ email_count: 5 }` | Job starts |
| `email_auto_scanned` | `{ subject, from, threat_status, severity }` | Each email processed |
| `auto_scan_completed` | `{ processed: 5, threats: 2 }` | Job completes |
| `auto_scan_failed` | `{ error: "..." }` | Job fails |
| `alert_digest_flushed` | `{ alert_count, batch_id }` | Hourly/daily flush |
| `cleanup_old_logs_ran` | `{ deleted_count, retention_days }` | Cleanup job runs |

**Frontend Listener**:
```javascript
// In email_scanner.html
socket.on('email_auto_scanned', (data) => {
    // Insert row into results table
    const row = `
        <tr>
            <td>${data.timestamp}</td>
            <td>${data.subject}</td>
            <td>${data.from}</td>
            <td>${data.threat_status}</td>
            <td><span class="badge">Auto</span></td>
        </tr>
    `;
    document.querySelector('#results-table tbody').insertAdjacentHTML('beforeend', row);
});
```

---

## Design Patterns

### 1. Service Layer Pattern

**Benefits**: Decouples API logic from route handlers

```python
# services/virustotal_service.py
class VirusTotalService:
    def query(self, indicator):
        # API-specific logic
        
    def parse_response(self, response):
        # Normalize response

# routes/lookup.py
from services.virustotal_service import VirusTotalService

@app.route('/api/lookup', methods=['POST'])
def lookup():
    vt = VirusTotalService()
    result = vt.query(request.json['indicator'])
    return result
```

### 2. Repository Pattern

**Benefits**: Abstraction layer for database queries

```python
class ThreatLogRepository:
    @staticmethod
    def save(threat_log):
        db.session.add(threat_log)
        db.session.commit()
    
    @staticmethod
    def get_by_url(url):
        return ThreatLog.query.filter_by(url=url).first()
    
    @staticmethod
    def get_high_severity_today():
        today = datetime.now().date()
        return ThreatLog.query.filter(
            ThreatLog.severity == 'High',
            ThreatLog.timestamp >= today
        ).all()
```

### 3. Caching Pattern

**Benefits**: Reduce database load, improve response times

```python
from functools import lru_cache
import time

class SettingsCache:
    _cache = {}
    _cache_time = None
    TTL = 60  # seconds
    
    @classmethod
    def get(cls):
        now = time.time()
        if cls._cache and (now - cls._cache_time) < cls.TTL:
            return cls._cache
        
        # Cache miss, load from DB
        cls._cache = load_settings_from_db()
        cls._cache_time = now
        return cls._cache
    
    @classmethod
    def invalidate(cls):
        cls._cache = {}
        cls._cache_time = None
```

---

## Database Schema

```sql
-- ThreatLog: Stores scanned threats
CREATE TABLE threat_log (
    id INTEGER PRIMARY KEY,
    category VARCHAR (50),      -- 'email', 'url', 'qr', 'log'
    url VARCHAR(500),
    status VARCHAR(20),         -- 'safe', 'malicious', 'suspicious'
    severity VARCHAR(20),       -- 'Low', 'Medium', 'High', 'Critical'
    flagged_reason TEXT,
    details JSON,
    timestamp DATETIME,
    auto_scan BOOLEAN,          -- True if from auto-scan job
    INDEX(category, timestamp)
);

-- Alert: Stores generated alerts
CREATE TABLE alert (
    id INTEGER PRIMARY KEY,
    type VARCHAR(50),           -- 'email_phishing', 'url_malicious', etc.
    source VARCHAR(100),
    severity VARCHAR(20),
    frequency VARCHAR(20),      -- 'immediate', 'hourly', 'daily'
    batch_id VARCHAR(100),
    timestamp DATETIME,
    INDEX(severity, timestamp)
);

-- AuditLog: Immutable audit trail
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    user_id VARCHAR(100),
    user_ip VARCHAR(100),
    action VARCHAR(100),        -- 'update_settings', 'delete_log', etc.
    changes JSON,               -- Per-field changes
    status VARCHAR(20),         -- 'success', 'failure'
    UNIQUE(id, timestamp)       -- Immutable constraint
);

-- Settings: System configuration
CREATE TABLE settings (
    id INTEGER PRIMARY KEY,
    key VARCHAR(100) UNIQUE,
    value JSON,
    updated_at DATETIME
);
```

---

## Scalability Considerations

### Current (Single Server)
- ✅ SQLite database
- ✅ In-memory settings cache
- ✅ APScheduler on single process
- ✅ Supports ~100 concurrent users

### Future (Enterprise Scale)
```
1. Database: SQLite → PostgreSQL
   └─ Supports >10K concurrent users
   
2. Caching: In-memory → Redis
   └─ Distributed cache across servers
   
3. Background Jobs: APScheduler → Celery + RabbitMQ
   └─ Multiple workers, distributed scheduling
   
4. API Rate Limiting: In-memory → Redis
   └─ Distributed rate limiting across servers
   
5. Frontend: Single server → CDN
   └─ Static assets cached globally
   
6. Load Balancing: None → nginx
   └─ Round-robin across multiple Flask instances
```

---

## Error Handling

### Strategy: Fail Gracefully

```python
# If VT API unavailable, use other APIs
try:
    vt_result = virustotal_service.query(url)
except Exception as e:
    logger.error(f"VT lookup failed: {e}")
    vt_result = None  # Continue without VT

# Combine results from all available APIs
final_result = {
    'virustotal': vt_result,
    'gemini': gemini_result,
    'abuseipdb': abuseipdb_result
}

# Make decision with partial data
severity = calculate_threat_severity(final_result)
```

---

## References

- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [12-Factor App](https://12factor.net/)

---

**For architecture questions, open an issue or contact: sabarish.edu2024@gmail.com**
