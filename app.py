import websocket
import json
import threading
import re
import time

# Define a regex pattern for basic SQL injection detection
sql_injection_pattern = re.compile(r"('|\"|\b)OR\s+1\s*=\s*1\b", re.IGNORECASE)

def on_message(ws, message):
    # This function will be called whenever a log is received from the WebSocket
    log_entry = json.loads(message)
    process_log(log_entry)  # Function to process each log

def on_error(ws, error):
    print(f"WebSocket error IDS: {error}\n\n")

def on_close(ws):
    print("WebSocket connection closed IDS\n\n")

def on_open(ws):
    print("WebSocket connection opened IDS\n\n")

def process_log(log_entry):
    # Check if this is a REQUEST log with a body to inspect
    if log_entry.get("type") == "REQUEST" and "body" in log_entry:
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
    websocket_url = "ws://packet_logger:5000/ws"
    tries = 0
    while tries < 5:
        try:
            # Initialize the WebSocket client
            ws = websocket.WebSocketApp(websocket_url,
                                        on_message=on_message,
                                        on_error=on_error,
                                        on_close=on_close)

            # Assign on_open to handle the connection
            ws.on_open = on_open

            # Run the WebSocket client and block until it closes
            ws.run_forever()

        except Exception as e:
            print(f"Failed to connect to WebSocket: {e}")
            print("Retrying connection in 5 seconds...")
            time.sleep(5)  # Wait 5 seconds before retrying
        tries += 1

if __name__ == "__main__":
    run_websocket_client()
