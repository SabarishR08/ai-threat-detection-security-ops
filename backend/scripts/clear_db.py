"""
Utility to clear application tables safely using SQLAlchemy.

Usage (preferred):
    python -m backend.scripts.clear_db --yes

Direct call fallback (adds project root to sys.path):
    python backend/scripts/clear_db.py --yes

Tables cleared:
- ThreatLog
- Alert
- BlacklistedIP
"""

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path when executed directly
CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[1]  # backend/
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_init import create_app
from extensions import db
from models import ThreatLog, Alert, BlacklistedIP


def clear_tables():
    """Delete all rows from core tables."""
    deleted = {"threat_logs": 0, "alerts": 0, "blacklisted_ips": 0}
    db.session.query(ThreatLog).delete()
    db.session.query(Alert).delete()
    db.session.query(BlacklistedIP).delete()
    db.session.commit()
    deleted["threat_logs"] = "cleared"
    deleted["alerts"] = "cleared"
    deleted["blacklisted_ips"] = "cleared"
    return deleted


def main(confirm: bool):
    if not confirm:
        print("⚠️  Add --yes to confirm clearing the database.")
        return

    app = create_app()
    with app.app_context():
        try:
            result = clear_tables()
            print(f"✅ Cleared tables: {result}")
        except Exception as exc:
            logging.exception("Failed to clear tables")
            print(f"❌ Failed to clear tables: {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clear application tables")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive operation")
    args = parser.parse_args()
    main(confirm=args.yes)
