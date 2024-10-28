# app.py (IDS Server)
import grpc
import os
from dotenv import load_dotenv
from concurrent import futures
import time
import json
from utils.RuleEngine import RuleEngine
import ids_pb2
import ids_pb2_grpc
from urllib.parse import quote_plus
import logging
import datetime

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Print to console
        logging.FileHandler('/app/ids_server.log')  # Save to file
    ]
)
logger = logging.getLogger('ids_server')

class IDSServicer(ids_pb2_grpc.IDSServicer):
    def __init__(self):
        
        # Get MongoDB connection details from environment variables
        mongo_user = os.getenv('MONGO_USER')
        mongo_user = quote_plus(mongo_user)
        mongo_password = os.getenv('MONGO_PASSWORD')
        mongo_password = quote_plus(mongo_password)
        mongo_port = os.getenv('MONGO_PORT')
        mongo_database = os.getenv('MONGO_DATABASE')
        
        # Construct MongoDB connection URL
        logger.info(f"Connecting to MongoDB at port {mongo_port}")
        mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"

        self.rule_engine = RuleEngine(mongo_url, 'ids_database', 'rules')
        logger.info("Loading rules from MongoDB...")
        self.rule_engine.load_rules()
        logger.info("Rules loaded successfully")
        logger.info("Loading ML model...")
        self.rule_engine.load_ml_model(
            model_path='models/ensemble_model.joblib',
            vectorizer_path='models/vectorizer.joblib'
        )
        logger.info("ML model loaded successfully")

    def ProcessLog(self, request, context):
        start_time = time.time()
        logger.info("\n" + "="*50)
        logger.info(f"Received log from client {request.client_id}")
        logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Client IP: {request.ip}")
        logger.info(f"Method: {request.method}")
        logger.info(f"Path: {request.path}")

        matched_rules = []
        if request.type == "REQUEST" and request.body:
            logger.info("Processing REQUEST with body")
            try:
                body_data = json.loads(request.body)
                
                # Check against all rules
                matched_rule = self.rule_engine.check_rules(body_data)
                if matched_rule:
                    matched_rules.append(matched_rule)
                    message = f"⚠️  Rule '{matched_rule}' matched"
                    print(f"\n{message}")
                    print(f"Matched payload: {request.body}")
                    return ids_pb2.ProcessResult(
                        injection_detected=True,
                        message=message,
                        matched_rules=matched_rules
                    )
                
                # If no rule matched, use ML model
                try:
                    logger.info("Running ML analysis...")
                    is_anomaly = self.rule_engine.predict_anomaly(body_data)
                    if is_anomaly:
                        logger.warning("ML model detected an anomaly")
                        new_rule_name = self.rule_engine.generate_rule_from_anomaly(body_data)
                        if new_rule_name:
                            matched_rules.append(new_rule_name)
                            message = f"🤖 ML model detected anomaly. Generated rule: {new_rule_name}"
                            logger.warning(f"Generated new rule: {new_rule_name}")
                        else:
                            message = "🤖 ML model detected anomaly"
                        print(message)
                        return ids_pb2.ProcessResult(
                            injection_detected=True,
                            message=message,
                            matched_rules=matched_rules
                        )
                    else:
                        message = f"✅ No anomalies detected for request from {request.ip} to {request.path}"
                        logger.info("ML analysis complete: No anomalies detected")
                        return ids_pb2.ProcessResult(
                            injection_detected=False,
                            message=message,
                            matched_rules=[]
                        )
                except Exception as e:
                    error_message = f"❌ Error in ML prediction: {e}"
                    logger.error(f"ML prediction error: {str(e)}")
                    return ids_pb2.ProcessResult(
                        injection_detected=False,
                        message=error_message,
                        matched_rules=[]
                    )
                    
            except json.JSONDecodeError:
                logger.error(f"JSON parsing error: {str(e)}")
                error_message = f"❌ Failed to parse body as JSON: {request.body[:100]}..."
                return ids_pb2.ProcessResult(
                    injection_detected=False,
                    message=error_message,
                    matched_rules=[]
                )
        else:
            logger.info("Non-REQUEST log or no body to inspect")
            message = "ℹ️  Non-REQUEST log or no body to inspect"
            return ids_pb2.ProcessResult(
                injection_detected=False,
                message=message,
                matched_rules=[]
            )

    def HealthCheck(self, request, context):
        print(f"Health check from client {request.client_id}")
        return ids_pb2.HealthCheckResponse(is_healthy=True)

def serve():
    # Load SSL/TLS certificates
    with open('certs/server.key', 'rb') as f:
        private_key = f.read()
    with open('certs/server.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('certs/ca.crt', 'rb') as f:
        root_certificates = f.read()
    
    logger.info("SSL certificates loaded successfully")

    # Create server credentials
    server_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True
    )

    logger.info("Server credentials created")

    server_options = [
        ('grpc.max_send_message_length', 1024 * 1024 * 100),
        ('grpc.max_receive_message_length', 1024 * 1024 * 100),
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 10000),
        ('grpc.keepalive_permit_without_calls', False),
        ('grpc.http2.min_time_between_pings_ms', 30000),
        ('grpc.http2.max_pings_without_data', 2),
        ('grpc.http2.min_ping_interval_without_data_ms', 30000)
    ]

    # Create gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=server_options
    )
    ids_pb2_grpc.add_IDSServicer_to_server(IDSServicer(), server)
    
    # Add secure port
    server_address = '0.0.0.0:50051'
    server.add_secure_port(server_address, server_credentials)
    
    logger.info(f"Starting IDS gRPC server on {server_address}")
    server.start()
    logger.info("Server started successfully")
    
    try:
        while True:
            server.wait_for_termination()  # Sleep for 24 hours
    except KeyboardInterrupt:
        logger.info("Shutting down IDS server...")
        server.stop(0)

if __name__ == '__main__':
    serve()