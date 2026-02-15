import os
import json

# ----------------------------
# Logs Configuration
# ----------------------------
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, "logs.json")

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def load_logs():
    """
    Load logs from the JSON file.
    Returns a list of log entries.
    """
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[Log Service] WARNING: Logs file corrupt. Starting new log.")
            return []
    return []

def save_log(entry):
    """
    Save a new log entry.
    Keeps only the latest 100 logs.
    """
    logs = load_logs()
    logs.insert(0, entry)  # newest first

    if len(logs) > 100:
        logs = logs[:100]

    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"[Log Service] Failed to save log: {e}")
