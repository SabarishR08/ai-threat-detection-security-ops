import time
from typing import Dict, Any

try:
    # Import load_settings from app context; avoid DB reads
    from . import app  # type: ignore
except Exception:
    app = None

# Fallback import if relative fails when used from app.py
try:
    from ..app import load_settings  # type: ignore
except Exception:
    load_settings = None

_CACHE: Dict[str, Any] | None = None
_CACHE_TS: float = 0.0
_TTL: int = 60  # seconds


def _load_structured_settings() -> Dict[str, Any]:
    if load_settings is None:
        # Minimal defaults if app import fails
        return {
            "alerts": {"enabled": True, "scope": "all", "frequency": "immediate"},
            "system": {"auto_scan": True, "log_retention_days": 30},
            "integrations": {"virustotal_configured": False},
        }
    s = load_settings()
    return {
        "alerts": {
            "enabled": bool(s.get("alerts_enabled", True)),
            "scope": s.get("alerts_scope", "all"),
            "frequency": s.get("alerts_frequency", "immediate"),
        },
        "system": {
            "auto_scan": bool(s.get("auto_scan", True)),
            "log_retention_days": int(s.get("log_retention_days", 30)),
        },
        "integrations": {
            "virustotal_configured": bool(s.get("virustotal_api_key")),
        },
    }


def get_settings() -> Dict[str, Any]:
    global _CACHE, _CACHE_TS
    now = time.time()
    if _CACHE is not None and (now - _CACHE_TS) < _TTL:
        return _CACHE
    _CACHE = _load_structured_settings()
    _CACHE_TS = now
    return _CACHE


def invalidate_settings_cache() -> None:
    global _CACHE_TS
    _CACHE_TS = 0.0
