import socketio
import json
import re
import time

# Define regex patterns for SQL injection detection
sql_injection_patterns = [
    re.compile(r"('|\b)OR\s+1\s*=\s*1\b", re.IGNORECASE),  # Existing pattern
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE)  # Pattern for ' OR '1'='1
]

sio = socketio.Client(logger=False, engineio_logger=False)

@sio.event
def connect():
    print("IDS: WebSocket connection opened")

@sio.event
def connect_error(data):
    print(f"IDS: Connection error: {data}")

@sio.event
def disconnect():
    print("IDS: WebSocket connection closed")

@sio.on('log')
def on_message(message):
    try:
        log_entry = json.loads(message)
        process_log(log_entry)
    except json.JSONDecodeError:
        print(f"IDS: Failed to parse message as JSON")

def process_log(log_entry):
    if log_entry.get("type") == "REQUEST" and log_entry.get("body"):
        try:
            body_data = json.loads(log_entry["body"])
        except json.JSONDecodeError:
            return

        username = body_data.get("username", "")
        password = body_data.get("password", "")

        # Check against all SQL injection patterns
        for pattern in sql_injection_patterns:
            if pattern.search(username) or pattern.search(password):
                print(f"""
IDS: SQL Injection detected!
Time: {log_entry['timestamp']}
IP: {log_entry['ip']}
Path: {log_entry['path']}
Method: {log_entry['method']}
Body: {log_entry['body']}
""")
                return

def run_websocket_client():
    tries = 0
    while tries < 5:
        try:
            sio.connect('http://packet_logger:5000', transports=['websocket'])
            sio.wait()
        except Exception as e:
            print(f"IDS: Failed to connect to WebSocket: {e}")
            print("IDS: Retrying connection in 5 seconds...")
            time.sleep(5)
        tries += 1

if __name__ == "__main__":
    print("IDS: Waiting for Packet Logger to start...")
    time.sleep(10)  # Wait for 10 seconds
    run_websocket_client()