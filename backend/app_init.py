# backend/app_init.py

import os
import logging
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

from backend.extensions import db, socketio, limiter, cors
from backend.utils.helpers import format_timestamp_ist
from backend.services.maintenance import cleanup_old_logs
from backend.utils.settings_service import get_settings
from backend.routes.dashboard import dashboard_bp
from backend.routes.threat_lookup import threat_lookup_bp
from backend.routes.qr import qr_bp
from backend.routes.soc import soc_bp
from backend.routes.email import email_bp
from backend.routes.common import common_bp
from backend.routes.admin import admin_bp
from backend.routes.monitoring import monitoring_bp
from backend.routes.performance import performance_bp
from backend.email_scanner_routes import email_scanner

def create_app():
    """Factory to create and configure the Flask app."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "dashboard", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "dashboard", "static"),
        static_url_path="/static"
    )

    # Load .env variables
    load_dotenv()

    # Ensure database folder exists
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_folder = os.path.join(base_dir, "database")
    os.makedirs(db_folder, exist_ok=True)

    # Database configuration (use absolute path for safety)
    db_path = os.path.join(db_folder, "threats.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", f"sqlite:///{db_path}")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Uploads and limits
    upload_dir = os.path.join(base_dir, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_dir
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

    # API keys and feature flags
    app.config["VIRUSTOTAL_API_KEY"] = os.getenv("VIRUSTOTAL_API_KEY")
    app.config["BREVO_API_KEY"] = os.getenv("BREVO_API_KEY")
    app.config["ALERT_EMAIL"] = os.getenv("ALERT_EMAIL")
    app.config["SENDER_EMAIL"] = os.getenv("SENDER_EMAIL")
    app.config["DEBUG_MODE"] = os.getenv("DEBUG", "True").lower() in ("1", "true", "yes")

    # Template helpers
    app.jinja_env.globals["format_timestamp_ist"] = format_timestamp_ist

    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    limiter.init_app(app)
    cors.init_app(app, resources={r"/*": {"origins": "*"}})

    # Logging setup
    os.makedirs(os.path.join(base_dir, "logs"), exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(base_dir, "logs", "app.log"),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(threat_lookup_bp)
    app.register_blueprint(qr_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(common_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(performance_bp)
    app.register_blueprint(email_scanner)

    # Create tables
    with app.app_context():
        db.create_all()
        # Clean up old logs using configured retention
        settings = get_settings()
        cleanup_old_logs(settings.log_retention_days)

    return app

