import socketio
import json
import re
import time

# Define a regex pattern for basic SQL injection detection
sql_injection_pattern = re.compile(r"('|\"|\b)OR\s+1\s*=\s*1\b", re.IGNORECASE)

sio = socketio.Client()

@sio.event
def connect():
    print("WebSocket connection opened IDS\n\n")

@sio.event
def disconnect():
    print("WebSocket connection closed IDS\n\n")

@sio.on('log')
def on_message(message):
    log_entry = json.loads(message)
    process_log(log_entry)


def process_log(log_entry):
    # Check if this is a REQUEST log with a body to inspect
    if log_entry.get("type") == "REQUEST" and log_entry.get("body"):
        try:
            body_data = json.loads(log_entry["body"])  # Parse body as JSON
        except json.JSONDecodeError:
            print(f"Failed to parse body as JSON IDS: {log_entry['body']}\n")
            return

        # Extract fields that may contain SQL injection, like username and password
        username = body_data.get("username", "")
        password = body_data.get("password", "")

        # Check if either the username or password contains a SQL injection pattern
        if sql_injection_pattern.search(username) or sql_injection_pattern.search(password):
            print(f"SQL Injection detected in log from {log_entry['ip']} on path {log_entry['path']}")
        else:
            print(f"No SQL Injection detected in log from {log_entry['ip']}\n")
    else:
        print(f"Non-REQUEST log or no body to inspect: {log_entry}\n")
        
def run_websocket_client():
    tries = 0
    while tries < 5:
        try:
            sio.connect('http://packet_logger:5000')
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
