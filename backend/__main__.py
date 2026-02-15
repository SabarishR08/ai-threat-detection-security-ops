# Allow running with: python -m backend
import os
from backend.app_init import create_app
from backend.extensions import socketio
from backend.background.init_services import initialize_background_services

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        initialize_background_services(app, socketio)
    debug = app.config.get("DEBUG_MODE", False)
    socketio.run(app, host="0.0.0.0", port=5000, debug=debug)
