"""
Centralized constants for the threat detection system.
"""

import pytz

# Timezone
IST = pytz.timezone('Asia/Kolkata')

# QR Upload validation
ALLOWED_QR_EXTS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB

# Alert thresholds
ALERT_COOLDOWN_SECONDS = 5
BACKGROUND_TASK_INTERVAL = 5  # seconds between threat log emissions
LOG_RETENTION_DAYS = 30

# Database
DATABASE_TABLES_INIT_WAIT = 1  # seconds

# Threat log categories
CATEGORY_EMAIL = "email"
CATEGORY_URL_SCAN = "url_scan"
CATEGORY_QR = "qr"
CATEGORY_SOC = "soc"
CATEGORY_THREAT_LOOKUP = "threat_lookup"

# Severity levels
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"

# VT status mapping
VT_STATUS_SAFE = "Safe"
VT_STATUS_SUSPICIOUS = "Suspicious"
VT_STATUS_MALICIOUS = "Malicious"
VT_STATUS_ERROR = "Error"
VT_STATUS_PENDING = "Pending"
VT_STATUS_MISSING_KEY = "VT_API_MISSING"
