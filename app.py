import grpc
from concurrent import futures
import ids_pb2
import ids_pb2_grpc
import json
import re
import time

# Define regex patterns for SQL injection detection
sql_injection_patterns = [
    re.compile(r"('|\b)OR\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE)
]

class IDSServicer(ids_pb2_grpc.IDSServicer):
    def ProcessLog(self, request, context):
        print(f"Processing log entry: {request}")
        
        injection_detected = False
        message = ""

        if request.type == "REQUEST" and request.body:
            try:
                body_data = json.loads(request.body)
                username = body_data.get("username", "")
                password = body_data.get("password", "")

                # Check against all SQL injection patterns
                for pattern in sql_injection_patterns:
                    if pattern.search(username) or pattern.search(password):
                        injection_detected = True
                        message = f"SQL Injection detected in log from {request.ip} on path {request.path}"
                        print(message)
                        break

                if not injection_detected:
                    message = f"No SQL Injection detected in log from {request.ip} on path {request.path}"
                    print(message)
            except json.JSONDecodeError:
                message = f"Failed to parse body as JSON: {request.body}"
                print(message)
        else:
            message = f"Non-REQUEST log or no body to inspect: {request}"
            print(message)

        return ids_pb2.ProcessResult(injection_detected=injection_detected, message=message)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ids_pb2_grpc.add_IDSServicer_to_server(IDSServicer(), server)
    
    with open('./ssl/ids_server.key', 'rb') as f:
        private_key = f.read()
    with open('./ssl/ids_server.crt', 'rb') as f:
        certificate_chain = f.read()
    
    server_credentials = grpc.ssl_server_credentials(
        ((private_key, certificate_chain),),
        root_certificates=open('ca.crt', 'rb').read(),
        require_client_auth=True
    )
    
    server.add_secure_port('[::]:50051', server_credentials)
    server.start()
    print("IDS Server started on port 50051 (SSL/TLS enabled with client authentication)")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()