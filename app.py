import json

import grpc
import os
from dotenv import load_dotenv
from concurrent import futures
from utils.RuleEngine import RuleEngine
import ids_pb2
import ids_pb2_grpc
from urllib.parse import quote_plus
from datetime import datetime
from utils.logger_config import logger

load_dotenv()


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
            model_path='models/model_info.joblib',
            vectorizer_path='models/vectorizer.joblib',
            preprocessor_path='models/preprocessor.joblib',
        )

    def ProcessLog(self, request, context):
        """Process incoming log requests with minimal logging."""
        try:
            # Split path and query
            path = request.path
            query = ''
            if '?' in path:
                path, query = path.split('?', 1)

            # Create analysis data
            analysis_data = {
                'timestamp': request.timestamp,
                'type': request.type,
                'ip': request.ip,
                'method': request.method,
                'path': path,
                'query': query,
                'headers': dict(request.headers),
                'body': request.body if request.body else '',
                'client_id': request.client_id
            }

            logger.info("=========== New Request Receieved =============")
            # Check rules first
            matched_rule = self.rule_engine.check_rules(analysis_data)
            if matched_rule:
                logger.warning(f"🚨 Attack detected (Rule: {matched_rule})")
                logger.warning(f"Request: {request.method} {path}?{query}")
                if request.body:
                    logger.warning(f"Body: {request.body}")

                return ids_pb2.ProcessResult(
                    injection_detected=True,
                    message=f"⚠️  Rule '{matched_rule}' matched",
                    matched_rules=[matched_rule]
                )

            # If no rule matches, use ML analysis
            try:
                is_anomaly, confidence = self.rule_engine.predict_anomaly(analysis_data)
                if is_anomaly:
                    new_rule_name = self.rule_engine.generate_rule_from_anomaly(analysis_data)

                    logger.warning(f"\n🚨 Attack detected (ML confidence: {confidence:.2f})")
                    logger.warning(f"Request: {request.method} {path}?{query}")
                    if request.body:
                        logger.warning(f"Body: {request.body}")
                    if new_rule_name:
                        logger.warning(f"Generated rule: {new_rule_name}")

                    return ids_pb2.ProcessResult(
                        injection_detected=True,
                        message=f"🤖 ML model detected anomaly" +
                                (f". Generated rule: {new_rule_name}" if new_rule_name else ""),
                        matched_rules=[new_rule_name] if new_rule_name else []
                    )
                else:
                    # Minimal logging for normal requests
                    logger.info(f"✅ {request.method} {path}")
                    return ids_pb2.ProcessResult(
                        injection_detected=False,
                        message="No anomalies detected",
                        matched_rules=[]
                    )
            except Exception as e:
                logger.error(f"ML analysis error: {str(e)}")
                return ids_pb2.ProcessResult(
                    injection_detected=False,
                    message=f"Request processed (ML error: {str(e)})",
                    matched_rules=[]
                )

        except Exception as e:
            logger.error(f"Request processing error: {str(e)}")
            return ids_pb2.ProcessResult(
                injection_detected=False,
                message=f"Error processing request: {str(e)}",
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
