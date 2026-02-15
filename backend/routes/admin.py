from flask import Blueprint, jsonify
from backend.models import SettingsAudit

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/api/settings_audit')
def api_settings_audit():
    entries = SettingsAudit.query.order_by(SettingsAudit.changed_at.desc()).limit(100).all()
    return jsonify({
        "entries": [
            {
                "changed_at": e.changed_at.strftime('%Y-%m-%d %H:%M:%S'),
                "field": e.field,
                "old_value": e.old_value,
                "new_value": e.new_value,
                "changed_by": e.changed_by,
            } for e in entries
        ]
    })
