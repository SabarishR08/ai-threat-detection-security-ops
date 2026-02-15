from flask import Blueprint, jsonify
from dashboard import socketio
import time

routes = Blueprint("routes", __name__)

@routes.route('/simulate_threat', methods=['GET'])
def simulate_threat():
    threat_data = {"ip": "192.168.1.100", "type": "Malware", "timestamp": time.time()}
    socketio.emit('new_threat', threat_data)  # Sends data to the dashboard
    return jsonify({"message": "Threat simulated", "data": threat_data}), 200
