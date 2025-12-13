# 🚀 DEPLOYMENT GUIDE

## Quick Start (5 minutes)

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Set Up Gmail OAuth2
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create project → Enable Gmail API
3. Create OAuth2 credentials (Desktop Application)
4. Download as JSON → Save to `backend/credentials/credentials.json`

### 3. Set Environment Variables
Create `backend/.env`:
```bash
VIRUSTOTAL_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
FLASK_ENV=development
SECRET_KEY=generate_secure_random_key
DEBUG=False
```

**Generate SECRET_KEY:**
```python
import secrets
print(secrets.token_urlsafe(32))
```

### 4. Run the App
```bash
cd backend
python app.py
```

Visit `http://localhost:5000`

---

## Production Deployment

### With Docker (Recommended)

Create `Dockerfile`:
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY dashboard/ ./dashboard

ENV FLASK_ENV=production
EXPOSE 5000

CMD ["python", "app.py"]
```

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./backend/credentials:/app/credentials
      - ./backend/logs:/app/logs
      - ./backend/database:/app/database
```

Run:
```bash
docker-compose up -d
```

---

## Environment Variables Explained

| Variable | Required | Example | Purpose |
|----------|----------|---------|---------|
| `VIRUSTOTAL_API_KEY` | Yes | `e7a48...` | URL/IP threat intelligence |
| `GEMINI_API_KEY` | Yes | `AIzaSyD...` | AI-powered threat analysis |
| `ABUSEIPDB_API_KEY` | Yes | `abc123...` | IP reputation checks |
| `FLASK_ENV` | No | `production` | Flask environment mode |
| `SECRET_KEY` | Yes | `aB3x9nK...` | Session encryption key |
| `DEBUG` | No | `False` | Disable debug mode in production |

---

## Getting Free API Keys

### VirusTotal
1. Go to https://www.virustotal.com/
2. Sign up → My API Key
3. Copy free tier API key
4. Limit: 4 requests/minute

### Google Gemini
1. Go to https://ai.google.dev/
2. Create API key
3. Enable in your project
4. Limit: 60 requests/minute (free)

### AbuseIPDB
1. Go to https://www.abuseipdb.com/
2. Create account → API
3. Copy API key
4. Limit: 1,000 requests/24h (free)

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'apscheduler'"
```bash
pip install APScheduler==3.10.4
# or
pip install -r requirements.txt
```

### "Gmail API credentials not found"
1. Ensure `backend/credentials/credentials.json` exists
2. Re-authenticate via OAuth2 flow
3. Check file permissions (should be readable)

### "CSRF Token Validation Failed"
- Clear browser cookies
- Refresh the page (new token fetched automatically)
- Check `SECRET_KEY` is set in `.env`

### Auto-scan not triggering
1. Check APScheduler is running (check logs)
2. Verify 5-minute interval in `app.py`
3. Ensure `backend/instance/last_email_scan.json` is writable

---

## Monitoring

### Check Logs
```bash
tail -f backend/logs.json  # Real-time logs
cat backend/logs.json | grep "ERROR"  # Errors only
```

### Check Auto-Scan Status
```bash
curl http://localhost:5000/api/auto_scan_status
```

### View Audit Logs
Login → Settings → Scroll down to "Audit Log"

---

## Scaling Tips

1. **Database**: Switch from SQLite to PostgreSQL for concurrency
```python
# In config.py
SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@localhost/db'
```

2. **Caching**: Use Redis for settings cache
```python
# core/settings_cache.py
cache.init_app(app, config={'CACHE_TYPE': 'redis'})
```

3. **Rate Limiting**: Use distributed rate limiter
```python
limiter = Limiter(storage_uri="redis://localhost:6379")
```

4. **Background Jobs**: Move to Celery for distributed workers
```python
# Instead of APScheduler
celery_app.task(bind=True)
def run_auto_scan(self):
    ...
```

---

## SSL/TLS Setup

### With Let's Encrypt
```bash
apt-get install certbot
certbot certonly --standalone -d yourdomain.com

# Point Flask to certificate
app.run(ssl_context=('/etc/letsencrypt/live/yourdomain.com/fullchain.pem',
                     '/etc/letsencrypt/live/yourdomain.com/privkey.pem'))
```

---

## Backup Strategy

### Daily Backup Script
```bash
#!/bin/bash
BACKUP_DIR="/backups/cyber-defense"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup database
cp backend/database/threat_db.db $BACKUP_DIR/threat_db_$TIMESTAMP.db

# Backup logs
cp backend/logs.json $BACKUP_DIR/logs_$TIMESTAMP.json

# Backup audit logs
cp backend/logs/audit.json $BACKUP_DIR/audit_$TIMESTAMP.json

# Keep last 30 days
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
```

---

## Monitoring & Alerting

### Send Alerts on High-Severity Threats
```python
# In backend/alert_service.py
if threat_severity == 'HIGH':
    send_email(admin_email, f"HIGH SEVERITY THREAT DETECTED: {threat_details}")
    send_slack_notification(f"🚨 {threat_details}")
```

### Uptime Monitoring
Use service like Uptime Robot:
```
URL: https://yourdomain.com/api/health
Expected: {"status": "ok"}
```

---

## Performance Optimization

1. **Enable Gzip Compression**
```python
from flask_compress import Compress
Compress(app)
```

2. **Add Caching Headers**
```python
@app.after_request
def add_cache_headers(response):
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response
```

3. **Database Indexing**
```python
class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    category = db.Column(db.String, index=True)
    timestamp = db.Column(db.DateTime, index=True)
```

---

## Support & Issues

See main [README.md](../README.md) for contact information.
