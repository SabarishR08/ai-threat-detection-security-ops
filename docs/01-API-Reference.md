# 📚 API DOCUMENTATION

## Base URL
```
http://localhost:5000
```

---

## Authentication

All endpoints use **session-based authentication**. Login at `/settings/login` first.

CSRF protection required: Include `X-CSRF-Token` header for POST/PUT/DELETE requests.

---

## Endpoints

### Settings Management

#### 1. Get CSRF Token
```http
GET /api/get_csrf_token
```

**Response:**
```json
{
  "csrf_token": "abc123def456..."
}
```

**Purpose**: Fetch CSRF token for session (required for form submissions)

---

#### 2. Get Settings
```http
GET /api/get_settings
```

**Response:**
```json
{
  "alerts": {
    "enabled": true,
    "scope": "all",
    "frequency": "immediate"
  },
  "integrations": {
    "virustotal_configured": true,
    "gemini_configured": true,
    "abuseipdb_configured": true
  },
  "system": {
    "log_retention_days": 30,
    "auto_scan_enabled": true
  }
}
```

**Note**: API keys are NOT returned (security feature)

---

#### 3. Update Settings
```http
POST /api/update_settings
Content-Type: application/json
X-CSRF-Token: {token}

{
  "alerts": {
    "enabled": true,
    "scope": "high-severity",
    "frequency": "hourly"
  },
  "system": {
    "log_retention_days": 90,
    "auto_scan_enabled": false
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Settings updated"
}
```

**Error Responses:**
- `419` - CSRF token invalid or missing
- `400` - Invalid settings format
- `429` - Rate limit exceeded (5/minute)

---

#### 4. Test VirusTotal API
```http
POST /api/test_virustotal
Content-Type: application/json
X-CSRF-Token: {token}

{
  "key": "your_api_key_here"
}
```

**Response (Success):**
```json
{
  "status": "ok",
  "message": "API key is valid"
}
```

**Response (Failure):**
```json
{
  "status": "error",
  "message": "Invalid API key"
}
```

---

### Email Scanning

#### 5. Scan Email
```http
POST /api/scan_email
Content-Type: application/json

{
  "email": "example@domain.com",
  "password": "app_password",
  "imap_server": "imap.gmail.com"
}
```

**Response:**
```json
{
  "emails_scanned": 5,
  "threats_found": 2,
  "results": [
    {
      "subject": "Urgent: Verify Your Account",
      "from": "fake@phishing.com",
      "is_phishing": true,
      "severity": "High",
      "urls": [
        {
          "url": "https://malicious.com/steal",
          "threat_status": "malicious",
          "detection_engine": "VirusTotal"
        }
      ]
    }
  ]
}
```

---

#### 6. Get Auto-Scan Status
```http
GET /api/auto_scan_status
```

**Response:**
```json
{
  "enabled": true,
  "last_run": "2025-12-13T14:30:00Z",
  "next_run": "2025-12-13T14:35:00Z",
  "last_processed_email_id": "18b9b7e2c1a3d4e5",
  "emails_processed_today": 47
}
```

---

### Threat Intelligence

#### 7. Lookup Threat
```http
POST /api/lookup_threat
Content-Type: application/json

{
  "indicator": "192.168.1.1",
  "type": "ip"
}
```

**Supported Types:**
- `ip` - IP address reputation
- `url` - URL/domain malware check
- `domain` - Domain registration info
- `email` - Email breach check

**Response:**
```json
{
  "indicator": "192.168.1.1",
  "type": "ip",
  "results": {
    "virustotal": {
      "last_analysis_stats": {
        "malicious": 2,
        "suspicious": 1,
        "undetected": 60
      }
    },
    "abuseipdb": {
      "abuseConfidenceScore": 75,
      "totalReports": 142,
      "usageType": "Data Center"
    },
    "whois": {
      "org": "Example ISP",
      "country": "US"
    }
  },
  "overall_risk": "High"
}
```

---

#### 8. Detect QR Code Threat
```http
POST /api/detect_qr
Content-Type: multipart/form-data

file: (binary image file)
```

**Response:**
```json
{
  "qr_detected": true,
  "qr_data": "https://malicious.com/click",
  "url_threat_status": "malicious",
  "redirects": [
    "https://malicious.com/click",
    "https://phishing.net/steal",
    "https://attacker.xyz"
  ],
  "risk_level": "Critical"
}
```

---

### Log Analysis

#### 9. Analyze SOC Logs
```http
POST /api/analyze_soc_logs
Content-Type: application/json

{
  "log_content": "...",
  "log_type": "windows"
}
```

**Supported Log Types:**
- `windows` - Windows Event Viewer logs
- `linux` - Linux syslog, auth.log
- `apache` - Apache access/error logs
- `nginx` - Nginx access logs

**Response:**
```json
{
  "anomalies": [
    {
      "type": "brute_force_attempt",
      "severity": "High",
      "details": "Multiple failed login attempts from 192.168.1.100",
      "count": 50,
      "timeframe": "5 minutes"
    },
    {
      "type": "privilege_escalation",
      "severity": "Critical",
      "details": "Unauthorized sudo access attempt",
      "user": "unknown",
      "timestamp": "2025-12-13T14:23:45Z"
    }
  ],
  "threat_score": 85
}
```

---

#### 10. Get Threat Logs
```http
GET /api/threat_logs?category=email&severity=High&limit=50&offset=0
```

**Query Parameters:**
- `category` - Filter by category (email, url, qr, log, soc)
- `severity` - Filter by severity (Low, Medium, High, Critical)
- `limit` - Max results (default 50)
- `offset` - Pagination offset (default 0)

**Response:**
```json
{
  "total": 247,
  "results": [
    {
      "id": 1,
      "category": "email",
      "url": "https://phishing.com",
      "status": "malicious",
      "severity": "High",
      "flagged_reason": "VirusTotal detection + Gemini ML score > 0.8",
      "details": {
        "vt_detections": 15,
        "gemini_confidence": 0.92
      },
      "timestamp": "2025-12-13T14:23:45Z",
      "auto_scan": false
    }
  ]
}
```

---

## Error Codes

| Code | Meaning | Example |
|------|---------|---------|
| `200` | Success | Settings updated |
| `400` | Bad request | Invalid JSON |
| `401` | Unauthorized | Not logged in |
| `403` | Forbidden | Access denied |
| `419` | CSRF token invalid | Token mismatch/expired |
| `429` | Rate limited | Too many requests |
| `500` | Server error | Unexpected error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/api/update_settings` | 5 per minute |
| `/api/scan_email` | 30 per hour (API quota limited) |
| `/api/lookup_threat` | 100 per hour |
| `/api/analyze_soc_logs` | 50 per hour |

---

## WebSocket Events (Socket.IO)

### Listening for Events

```javascript
socket.on('auto_scan_started', (data) => {
  console.log(`Auto-scan started, processing ${data.email_count} emails`);
});

socket.on('email_auto_scanned', (data) => {
  console.log(`Email scanned: ${data.subject}`);
  // Insert row in table
});

socket.on('auto_scan_completed', (data) => {
  console.log(`Auto-scan completed: ${data.processed} emails, ${data.threats} threats`);
});

socket.on('alert_digest_flushed', (data) => {
  console.log(`Digest flushed: ${data.alert_count} alerts`);
});
```

### Event Details

| Event | Payload |
|-------|---------|
| `auto_scan_started` | `{ email_count: int }` |
| `email_auto_scanned` | `{ subject, from, threat_status, severity, timestamp }` |
| `auto_scan_completed` | `{ processed: int, threats: int, duration_seconds: float }` |
| `auto_scan_failed` | `{ error: string }` |
| `alert_digest_flushed` | `{ alert_count: int, batch_id: string }` |
| `cleanup_old_logs_ran` | `{ deleted_count: int, retention_days: int }` |

---

## Example Usage

### Python Client

```python
import requests
import json

BASE_URL = "http://localhost:5000"
session = requests.Session()

# 1. Get CSRF token
token_response = session.get(f"{BASE_URL}/api/get_csrf_token")
csrf_token = token_response.json()['csrf_token']

# 2. Update settings
headers = {'X-CSRF-Token': csrf_token}
settings = {
    'system': {'auto_scan_enabled': True, 'log_retention_days': 90}
}
response = session.post(
    f"{BASE_URL}/api/update_settings",
    json=settings,
    headers=headers
)
print(response.json())

# 3. Lookup threat
response = session.post(
    f"{BASE_URL}/api/lookup_threat",
    json={'indicator': '8.8.8.8', 'type': 'ip'}
)
print(response.json())
```

### JavaScript Client

```javascript
// Get CSRF token
const csrfRes = await fetch('/api/get_csrf_token');
const { csrf_token } = await csrfRes.json();

// Update settings
const settingsRes = await fetch('/api/update_settings', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': csrf_token,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        system: { auto_scan_enabled: true }
    })
});
console.log(await settingsRes.json());
```

---

## Support

For API issues, refer to:
- [DEPLOYMENT.md](DEPLOYMENT.md) - Troubleshooting
- [SECURITY.md](SECURITY.md) - Security details
- GitHub Issues - Bug reports

---

**API Last Updated: December 2025**
