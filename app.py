import socketio
import json
import re
import time

# Define regex patterns for SQL injection detection
sql_injection_patterns = [
    re.compile(r"('|\b)OR\s+1\s*=\s*1\b", re.IGNORECASE),  # Existing pattern
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE)  # Pattern for ' OR '1'='1
]

sio = socketio.Client(logger=True, engineio_logger=True)

@sio.event
def connect():
    print("WebSocket connection opened IDS\n\n")

@sio.event
def connect_error(data):
    print(f"Connection error: {data}\n\n")

@sio.event
def disconnect():
    print("WebSocket connection closed IDS\n\n")

@sio.on('*')
def catch_all(event, data):
    print(f"Caught event: {event}")
    print(f"Data: {data}\n")

@sio.on('log')
def on_message(message):
    print(f"Received log message: {message}\n")
    try:
        log_entry = json.loads(message)
        process_log(log_entry)
    except json.JSONDecodeError:
        print(f"Failed to parse message as JSON: {message}\n")

def process_log(log_entry):
    print(f"Processing log entry: {log_entry}\n")
    if log_entry.get("type") == "REQUEST" and log_entry.get("body"):
        try:
            body_data = json.loads(log_entry["body"])
        except json.JSONDecodeError:
            print(f"Failed to parse body as JSON IDS: {log_entry['body']}\n")
            return

        username = body_data.get("username", "")
        password = body_data.get("password", "")

        injection_detected = False
        # Check against all SQL injection patterns
        for pattern in sql_injection_patterns:
            if pattern.search(username) or pattern.search(password):
                print(f"SQL Injection detected in log: {log_entry}")
                injection_detected = True
                break

        if not injection_detected:
            print(f"No SQL Injection detected in log from {log_entry['ip']} on path {log_entry['path']}\n")
    else:
        print(f"Non-REQUEST log or no body to inspect: {log_entry}\n")

def run_websocket_client():
    tries = 0
    while tries < 5:
        try:
            print(f"Attempting to connect to WebSocket (attempt {tries + 1})...")
            sio.connect('http://packet_logger:5000', transports=['websocket'])
            sio.wait()
        except Exception as e:
            print(f"Failed to connect to WebSocket: {e}")
            print("Retrying connection in 5 seconds...")
            time.sleep(5)
        tries += 1

if __name__ == "__main__":
    print("Waiting for Packet Logger to start...")
    time.sleep(10)  # Wait for 10 seconds
    run_websocket_client()