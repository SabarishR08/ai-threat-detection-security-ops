import os
import sys
from pathlib import Path
from flask import redirect, url_for

# Ensure project root is on sys.path when running `python app.py` from backend/
if __package__ is None:
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

# Use absolute package imports; canonical run: python -m backend
from backend.app_init import create_app
from backend.extensions import socketio
from backend.background.init_services import initialize_background_services
from backend.utils.helpers import get_client_ip
from backend.models import BlacklistedIP

# Entry-point only: build app via factory
app = create_app()

# IP blocking middleware using safe client IP extraction
@app.before_request
def block_malicious_ips():
    from flask import request, jsonify
    import logging
    try:
        client_ip = get_client_ip(request)
        if BlacklistedIP.query.filter_by(ip_address=client_ip).first():
            logging.warning(f"Blocked access from malicious IP: {client_ip}")
            return jsonify({"error": "Access Denied - Malicious IP detected"}), 403
    except Exception as e:
        logging.error(f"block_malicious_ips error: {e}")
        return None


if __name__ == "__main__":
    with app.app_context():
        initialize_background_services(app, socketio)
    debug = app.config.get("DEBUG_MODE", False)
    socketio.run(app, host="0.0.0.0", port=5000, debug=debug)