import websocket
import json
import threading

def on_message(ws, message):
    # This function will be called whenever a log is received from the WebSocket
    log_entry = json.loads(message)
    process_log(log_entry)  # Function to process each log

def on_error(ws, error):
    print(f"WebSocket error: {error}\n\n")

def on_close(ws):
    print("WebSocket connection closed\n\n")

def on_open(ws):
    print("WebSocket connection opened\n\n")

def process_log(log_entry):
    # Log processing logic (basic for now, extend with IDS logic later)
    print(f"Processing log: {log_entry}\n\n")

def main():
    # URL of the WebSocket server (log parser app)
    websocket_url = "ws://localhost:5000/socket.io/"  # Adjust the port and URL as needed

    # Initialize the WebSocket client
    ws = websocket.WebSocketApp(websocket_url,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)

    # Assign on_open to handle the connection
    ws.on_open = on_open

    # Run the WebSocket client in a thread so it doesn't block the main app
    threading.Thread(target=ws.run_forever).start()

if __name__ == "__main__":
    main()
