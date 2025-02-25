import sys

import json
import grpc
import os
import sys
import gc
import traceback
import contextlib
from dotenv import load_dotenv
from concurrent import futures
from utils.RuleEngine import RuleEngine
import ids_pb2
import ids_pb2_grpc
from urllib.parse import quote_plus
from datetime import datetime
from pymongo import MongoClient

# Import logger first so we can use it for startup logs
from utils.logger_config import logger

def log_exception(e):
    """Log exception details using the configured logger"""
    logger.error(f"Exception occurred: {str(e)}")
    logger.error(f"Exception type: {type(e)}")
    logger.error("Exception traceback:")
    for line in traceback.format_exc().split("\n"):
        logger.error(line)

# Start application
logger.info("Starting application...")
try:
    # Load environment variables
    load_dotenv()
    logger.info("Environment variables loaded")

    # Test environment variables
    required_vars = ['MONGO_USER', 'MONGO_PASSWORD', 'MONGO_PORT', 'MONGO_DATABASE']
    for var in required_vars:
        value = os.getenv(var)
        logger.info(f"{var}: {'Present' if value else 'Missing'}")

except Exception as e:
    log_exception(e)
    raise e


class IDSServicer(ids_pb2_grpc.IDSServicer):
    def __init__(self):
        try:
            logger.info("Initializing IDSServicer...")
            mongo_user = quote_plus(os.getenv('MONGO_USER'))
            mongo_password = quote_plus(os.getenv('MONGO_PASSWORD'))
            mongo_port = os.getenv('MONGO_PORT')
            mongo_database = os.getenv('MONGO_DATABASE')

            # Create mongo_url without logging the credentials
            mongo_url = f"mongodb://{mongo_user}:****@mongodb:{mongo_port}/{mongo_database}?authSource=admin"
            logger.info(f"Connecting to MongoDB at: {mongo_url.replace(mongo_user, '****')}")
            
            # Create the actual connection URL (not logged)
            actual_mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"
            
            # Set up MongoDB with connection pooling and timeouts
            self.mongo_client = MongoClient(
                actual_mongo_url,
                connectTimeoutMS=5000,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=20
            )
            self.db = self.mongo_client[mongo_database]
            logger.info("MongoDB client created")

            # Test the MongoDB connection
            collections = self.db.list_collection_names()
            logger.info(f"Available collections: {collections}")

            # Create logs collection if it doesn't exist
            if 'logs' not in collections:
                logger.info("Creating logs collection...")
                self.db.create_collection('logs')
                logger.info("Logs collection created")
            else:
                logger.info("Logs collection already exists")

            # Initialize RuleEngine (use same credentials but don't pass them directly)
            logger.info("Initializing RuleEngine...")
            self.rule_engine = RuleEngine(actual_mongo_url, mongo_database, 'rules')
            self.rule_engine.load_rules()
            logger.info("Rules loaded")
            
            # Load ML model components with proper error handling
            try:
                # Load the complete model package from Cicada
                # Standardize on the 'model' directory for consistency with Cicada
                model_path = 'model/complete_model_package.joblib'
                
                # Try to load the complete model package
                if os.path.exists(model_path):
                    try:
                        self.rule_engine.load_ml_model(model_path=model_path)
                        logger.info(f"Complete Cicada model package loaded successfully")
                    except Exception as e:
                        logger.warning(f"Failed to load Cicada model package: {str(e)}")
                        # Fall back to individual components
                        logger.warning("Falling back to individual model components")
                        self.rule_engine.load_ml_model(
                            model_path='model/model_info.joblib',
                            vectorizer_path='model/vectorizer.joblib',
                            preprocessor_path='model/preprocessor.joblib',
                        )
                        logger.info("Individual ML model components loaded successfully")
                else:
                    logger.warning("Cicada model package not found, loading individual components")
                    self.rule_engine.load_ml_model(
                        model_path='model/model_info.joblib',
                        vectorizer_path='model/vectorizer.joblib',
                        preprocessor_path='model/preprocessor.joblib',
                    )
                    logger.info("Individual ML model components loaded successfully")
            except Exception as ml_error:
                logger.error(f"Failed to load ML model: {str(ml_error)}")
                logger.warning("System will fall back to rule-based detection only")

        except Exception as e:
            log_exception(e)
            raise e

    def store_log_entry(self, analysis_data, is_attack, message, matched_rules=None):
        """Helper method to store log entries in MongoDB"""
        try:
            log_entry = {
                'timestamp': analysis_data['timestamp'],
                'type': analysis_data['type'],
                'ip': analysis_data['ip'],
                'method': analysis_data['method'],
                'path': analysis_data['path'],
                'query': analysis_data['query'],
                'headers': analysis_data['headers'],
                'body': analysis_data['body'],
                'client_id': analysis_data['client_id'],
                'analysis_result': {
                    'injection_detected': is_attack,
                    'message': message,
                    'matched_rules': matched_rules if matched_rules else []
                }
            }
            result = self.db.logs.insert_one(log_entry)
            logger.debug(f"Log entry stored with ID: {result.inserted_id}")
                
        except Exception as e:
            logger.error(f"Failed to store log in MongoDB: {str(e)}")
            logger.exception("Full traceback:")
            raise e

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

            logger.info("=========== New Request Received =============")
            # Check rules first
            matched_rule = self.rule_engine.check_rules(analysis_data)
            if matched_rule:
                message = f"⚠️  Rule '{matched_rule}' matched"
                logger.warning(f"🚨 Attack detected (Rule: {matched_rule})")
                logger.warning(f"Request: {request.method} {path}?{query}")
                logger.warning(f"Body: {request.body if request.body is not None else '<empty>'}")

                # Store attack log
                self.store_log_entry(analysis_data, True, message, [matched_rule])

                return ids_pb2.ProcessResult(
                    injection_detected=True,
                    message=message,
                    matched_rules=[matched_rule]
                )

            # If no rule matches, use ML analysis
            try:
                is_anomaly, confidence = self.rule_engine.predict_anomaly(analysis_data)
                if is_anomaly:
                    new_rule_name = self.rule_engine.generate_rule_from_anomaly(analysis_data)
                    message = f"🤖 ML model detected anomaly" + (f". Generated rule: {new_rule_name}" if new_rule_name else "")

                    logger.warning(f"\n🚨 Attack detected (ML confidence: {confidence:.2f})")
                    logger.warning(f"Request: {request.method} {path}?{query}")
                    logger.warning(f"Body: {request.body if request.body is not None else '<empty>'}")
                    if new_rule_name:
                        logger.warning(f"Generated rule: {new_rule_name}")

                    # Store ML-detected attack log
                    self.store_log_entry(analysis_data, True, message, [new_rule_name] if new_rule_name else [])

                    return ids_pb2.ProcessResult(
                        injection_detected=True,
                        message=message,
                        matched_rules=[new_rule_name] if new_rule_name else []
                    )
                else:
                    message = "No anomalies detected"
                    logger.info(f"✅ {request.method} {path}")

                    # Store normal request log
                    self.store_log_entry(analysis_data, False, message)

                    return ids_pb2.ProcessResult(
                        injection_detected=False,
                        message=message,
                        matched_rules=[]
                    )
            except Exception as e:
                message = f"Request processed (ML error: {str(e)})"
                logger.error(f"ML analysis error: {str(e)}")

                # Store error log
                self.store_log_entry(analysis_data, False, message)

                return ids_pb2.ProcessResult(
                    injection_detected=False,
                    message=message,
                    matched_rules=[]
                )

        except Exception as e:
            message = f"Error processing request: {str(e)}"
            logger.error(f"Request processing error: {str(e)}")

            # Store error log if we have analysis_data
            if 'analysis_data' in locals():
                self.store_log_entry(analysis_data, False, message)

            return ids_pb2.ProcessResult(
                injection_detected=False,
                message=message,
                matched_rules=[]
            )

    def HealthCheck(self, request, context):
        return ids_pb2.HealthCheckResponse(is_healthy=True)
    
def serve():
    try:
        logger.info("Starting server...")
        
        # Load SSL/TLS certificates with validation
        cert_files = {
            'private_key': 'certs/server.key',
            'certificate_chain': 'certs/server.crt',
            'root_certificates': 'certs/ca.crt'
        }
        
        # Check if certificate files exist
        for name, path in cert_files.items():
            if not os.path.exists(path):
                raise FileNotFoundError(f"Certificate file not found: {path}")
                
        # Load the certificate files
        with open(cert_files['private_key'], 'rb') as f:
            private_key = f.read()
        with open(cert_files['certificate_chain'], 'rb') as f:
            certificate_chain = f.read()
        with open(cert_files['root_certificates'], 'rb') as f:
            root_certificates = f.read()
            
        logger.info("Certificates loaded successfully")

        server_credentials = grpc.ssl_server_credentials(
            [(private_key, certificate_chain)],
            root_certificates=root_certificates,
            require_client_auth=True
        )

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        ids_pb2_grpc.add_IDSServicer_to_server(IDSServicer(), server)
        
        server_address = '0.0.0.0:50051'
        server.add_secure_port(server_address, server_credentials)
        logger.info("Server configured")

        server.start()
        logger.info("Server started successfully")
        
        # Register cleanup handler to properly close MongoDB connections on shutdown
        import atexit
        
        def cleanup():
            """Clean up resources when server is shutting down"""
            logger.info("Server shutting down, cleaning up resources...")
            # Close any active MongoDB connections
            try:
                # Find all instances of IDSServicer
                for servicer in [s for s in gc.get_objects() if isinstance(s, IDSServicer)]:
                    if hasattr(servicer, 'mongo_client') and servicer.mongo_client:
                        servicer.mongo_client.close()
                        logger.info("Closed MongoDB connection")
                    if hasattr(servicer, 'rule_engine') and hasattr(servicer.rule_engine, 'client'):
                        servicer.rule_engine.client.close()
                        logger.info("Closed RuleEngine MongoDB connection")
            except Exception as e:
                logger.error(f"Error during cleanup: {str(e)}")
        
        atexit.register(cleanup)
        
        # Wait for server termination
        server.wait_for_termination()
        
    except Exception as e:
        log_exception(e)
        raise e

if __name__ == '__main__':
    try:
        serve()
    except Exception as e:
        log_exception(e)
        sys.exit(1)