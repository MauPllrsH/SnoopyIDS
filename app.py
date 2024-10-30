import grpc
import os
from dotenv import load_dotenv
from concurrent import futures
from utils.RuleEngine import RuleEngine
import ids_pb2
import ids_pb2_grpc
from urllib.parse import quote_plus
import logging
from datetime import datetime

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/ids_server.log')
    ]
)
logger = logging.getLogger('ids_server')

class IDSServicer(ids_pb2_grpc.IDSServicer):
    def __init__(self):
        mongo_user = quote_plus(os.getenv('MONGO_USER'))
        mongo_password = quote_plus(os.getenv('MONGO_PASSWORD'))
        mongo_port = os.getenv('MONGO_PORT')
        mongo_database = os.getenv('MONGO_DATABASE')
        
        mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"

        self.rule_engine = RuleEngine(mongo_url, 'ids_database', 'rules')
        self.rule_engine.load_rules()
        self.rule_engine.load_ml_model(
            model_path='models/ensemble_model.joblib',
            vectorizer_path='models/vectorizer.joblib',
            preprocessor_path='models/preprocessor.joblib',
            label_encoder_path='models/label_encoder.joblib'
        )

    def ProcessLog(self, request, context):
        logger.info("\n=== NEW REQUEST RECEIVED ===")
        
        if request.type == "REQUEST":
            logger.info("SENT TO RULES...")
            
            try:
                # Create analysis data from the request fields
                analysis_data = {
                    'timestamp': request.timestamp,
                    'type': request.type,
                    'ip': request.ip,
                    'method': request.method,
                    'path': request.path,
                    'headers': dict(request.headers),
                    'body': request.body if request.body else '',
                    'client_id': request.client_id
                }
                
                # Run rule engine checks
                matched_rule = self.rule_engine.check_rules(analysis_data)
                if matched_rule:
                    message = f"⚠️  Rule '{matched_rule}' matched"
                    logger.warning(f"RULES RESPONSE: {message}")
                    logger.info("FINAL DECISION = ATTACK DETECTED")
                    return ids_pb2.ProcessResult(
                        injection_detected=True,
                        message=message,
                        matched_rules=[matched_rule]
                    )
                
                # If no rule matches, use ML analysis
                logger.info("SENT TO ML...")
                try:
                    is_anomaly = self.rule_engine.predict_anomaly(analysis_data)
                    if is_anomaly:
                        new_rule_name = self.rule_engine.generate_rule_from_anomaly(analysis_data)
                        message = f"🤖 ML model detected anomaly" + (f". Generated rule: {new_rule_name}" if new_rule_name else "")
                        logger.warning(f"ML RESPONSE: {message}")
                        logger.info("FINAL DECISION = ATTACK DETECTED")
                        return ids_pb2.ProcessResult(
                            injection_detected=True,
                            message=message,
                            matched_rules=[new_rule_name] if new_rule_name else []
                        )
                    else:
                        message = "✅ No anomalies detected"
                        logger.info(f"ML RESPONSE: {message}")
                        logger.info("FINAL DECISION = NO ATTACK DETECTED")
                        return ids_pb2.ProcessResult(
                            injection_detected=False,
                            message=message,
                            matched_rules=[]
                        )
                except Exception as e:
                    message = f"Request processed (ML error: {str(e)})"
                    logger.error(f"ML RESPONSE: Error in analysis")
                    logger.info("FINAL DECISION = ERROR IN PROCESSING")
                    return ids_pb2.ProcessResult(
                        injection_detected=False,
                        message=message,
                        matched_rules=[]
                    )
                    
            except Exception as e:
                message = f"Error processing request: {str(e)}"
                logger.error(f"Error: {message}")
                logger.info("FINAL DECISION = ERROR IN PROCESSING")
                return ids_pb2.ProcessResult(
                    injection_detected=False,
                    message=message,
                    matched_rules=[]
                )
        else:
            message = "Request processed (no analysis required)"
            logger.info(f"FINAL DECISION = {message}")
            return ids_pb2.ProcessResult(
                injection_detected=False,
                message=message,
                matched_rules=[]
            )

    def HealthCheck(self, request, context):
        return ids_pb2.HealthCheckResponse(is_healthy=True)

def serve():
    # Load SSL/TLS certificates
    with open('certs/server.key', 'rb') as f:
        private_key = f.read()
    with open('certs/server.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('certs/ca.crt', 'rb') as f:
        root_certificates = f.read()

    server_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True
    )

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

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=server_options
    )
    ids_pb2_grpc.add_IDSServicer_to_server(IDSServicer(), server)
    
    server_address = '0.0.0.0:50051'
    server.add_secure_port(server_address, server_credentials)
    
    logger.info("Starting IDS Server")
    server.start()
    
    try:
        while True:
            server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down IDS server")
        server.stop(0)

if __name__ == '__main__':
    serve()