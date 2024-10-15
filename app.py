import socketio
import json
import time

from model.RuleEngine import RuleEngine

sio = socketio.Client(logger=True, engineio_logger=True)
rule_engine = RuleEngine('mongodb://localhost:27017', 'ids_database', 'rules')


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

        # Check against all rules
        matched_rule = rule_engine.check_rules(body_data)
        if matched_rule:
            print(f"Rule '{matched_rule}' matched in log: {log_entry}")
        else:
            print(f"No rules matched in log from {log_entry['ip']} on path {log_entry['path']}\n")
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
    print("Loading rules from MongoDB...")
    rule_engine.load_rules()
    print("Waiting for Packet Logger to start...")
    time.sleep(10)  # Wait for 10 seconds
    run_websocket_client()
