"""
WebSocket Emitter - Real-time threat log broadcasting
Runs in background thread
"""
import time
import logging
import threading
from backend.models import ThreatLog

_running = False
_thread = None

def generate_threat_logs(app, socketio):
    """
    Background thread that emits latest threat logs via WebSocket
    """
    global _running
    while _running:
        time.sleep(5)
        try:
            with app.app_context():
                latest = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).first()
                if latest:
                    socketio.emit(
                        "threat_log",
                        {
                            "message": "New Threat Detected!",
                            "threat": {
                                "id": latest.id,
                                "timestamp": latest.timestamp.isoformat(),
                                "category": latest.category,
                                "url": latest.url,
                                "status": latest.status,
                                "flagged_reason": latest.flagged_reason,
                                "severity": latest.severity,
                                "details": latest.details,
                            },
                        }
                    )
        except Exception as e:
            logging.error(f"generate_threat_logs error: {e}")


def start_websocket_emitter(app, socketio):
    """Start the WebSocket background emitter thread"""
    global _running, _thread
    if not _running:
        _running = True
        _thread = threading.Thread(
            target=generate_threat_logs,
            args=(app, socketio),
            daemon=True
        )
        _thread.start()
        logging.info("WebSocket emitter thread started")


def stop_websocket_emitter():
    """Stop the WebSocket background emitter thread"""
    global _running
    _running = False
    logging.info("WebSocket emitter thread stopped")
