import sys

def log_exception(e):
    print(f"Exception occurred: {str(e)}", file=sys.stderr)
    print("Exception type:", type(e), file=sys.stderr)
    print("Exception traceback:", file=sys.stderr)
    import traceback
    traceback.print_exc()

print("Starting application...")
try:
    print("Importing modules...")
    import json
    import grpc
    import os
    from dotenv import load_dotenv
    from concurrent import futures
    from utils.RuleEngine import RuleEngine
    import waf_pb2
    import waf_pb2_grpc
    from urllib.parse import quote_plus
    from datetime import datetime
    from utils.logger_config import logger
    from pymongo import MongoClient
    print("All modules imported successfully")

    load_dotenv()
    print("Environment variables loaded")

    # Test environment variables
    required_vars = ['MONGO_USER', 'MONGO_PASSWORD', 'MONGO_PORT', 'MONGO_DATABASE']
    for var in required_vars:
        value = os.getenv(var)
        print(f"{var}: {'Present' if value else 'Missing'}")

except Exception as e:
    log_exception(e)
    raise e


class WAFServicer(waf_pb2_grpc.WAFServicer):
    def __init__(self):
        try:
            print("Initializing WAFServicer...")
            mongo_user = quote_plus(os.getenv('MONGO_USER'))
            mongo_password = quote_plus(os.getenv('MONGO_PASSWORD'))
            mongo_port = os.getenv('MONGO_PORT')
            mongo_database = os.getenv('MONGO_DATABASE')

            mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"
            print(f"Connecting to MongoDB at: {mongo_url}")

            self.mongo_client = MongoClient(mongo_url)
            self.db = self.mongo_client[mongo_database]
            print("MongoDB client created")

            # Test the MongoDB connection
            collections = self.db.list_collection_names()
            print(f"Available collections: {collections}")

            # Create logs collection if it doesn't exist
            if 'logs' not in collections:
                print("Creating logs collection...")
                self.db.create_collection('logs')
                print("Logs collection created")
            else:
                print("Logs collection already exists")

            # Add prevention mode state and collection
            self.prevention_mode = False
            if 'config' not in collections:
                print("Creating config collection...")
                self.db.create_collection('config')
                self.db.config.insert_one({'key': 'prevention_mode', 'enabled': False})
                print("Config collection created")
            else:
                # Load prevention mode state from MongoDB
                config = self.db.config.find_one({'key': 'prevention_mode'})
                if config:
                    self.prevention_mode = config['enabled']
                    print(f"Prevention mode loaded: {self.prevention_mode}")

            # Initialize RuleEngine
            print("Initializing RuleEngine...")
            self.rule_engine = RuleEngine(mongo_url, 'ids_database', 'rules')
            self.rule_engine.load_rules()
            print("Rules loaded")

            self.rule_engine.load_ml_model(
                model_path='models/model_info.joblib',
                vectorizer_path='models/vectorizer.joblib',
                preprocessor_path='models/preprocessor.joblib',
            )
            print("ML model loaded")

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
            logger.info(f"Log entry stored with ID: {result.inserted_id}")
            
            # Verify the entry was stored
            stored_entry = self.db.logs.find_one({'_id': result.inserted_id})
            if stored_entry:
                logger.info("Successfully verified log entry storage")
            else:
                logger.error("Failed to verify log entry storage")
                
        except Exception as e:
            logger.error(f"Failed to store log in MongoDB: {str(e)}")
            logger.exception("Full traceback:")

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

                return waf_pb2.ProcessResult(
                    injection_detected=True,
                    message=message,
                    matched_rules=[matched_rule],
                    should_block=self.prevention_mode  # Add blocking decision
                )

            # If no rule matches, use ML analysis
            try:
                is_anomaly, confidence = self.rule_engine.predict_anomaly(analysis_data)
                if is_anomaly:
                    new_rule_name = self.rule_engine.generate_rule_from_anomaly(analysis_data)
                    message = f"🤖 ML model detected anomaly" + (
                        f". Generated rule: {new_rule_name}" if new_rule_name else "")

                    logger.warning(f"\n🚨 Attack detected (ML confidence: {confidence:.2f})")
                    logger.warning(f"Request: {request.method} {path}?{query}")
                    logger.warning(f"Body: {request.body if request.body is not None else '<empty>'}")
                    if new_rule_name:
                        logger.warning(f"Generated rule: {new_rule_name}")

                    # Store ML-detected attack log
                    self.store_log_entry(analysis_data, True, message, [new_rule_name] if new_rule_name else [])

                    return waf_pb2.ProcessResult(
                        injection_detected=True,
                        message=message,
                        matched_rules=[new_rule_name] if new_rule_name else [],
                        should_block=self.prevention_mode  # Add blocking decision
                    )
                else:
                    message = "No anomalies detected"
                    logger.info(f"✅ {request.method} {path}")

                    # Store normal request log
                    self.store_log_entry(analysis_data, False, message)

                    return waf_pb2.ProcessResult(
                        injection_detected=False,
                        message=message,
                        matched_rules=[],
                        should_block=False
                    )
            except Exception as e:
                message = f"Request processed (ML error: {str(e)})"
                logger.error(f"ML analysis error: {str(e)}")

                # Store error log
                self.store_log_entry(analysis_data, False, message)

                return waf_pb2.ProcessResult(
                    injection_detected=False,
                    message=message,
                    matched_rules=[],
                    should_block=False
                )

        except Exception as e:
            message = f"Error processing request: {str(e)}"
            logger.error(f"Request processing error: {str(e)}")

            return waf_pb2.ProcessResult(
                injection_detected=False,
                message=message,
                matched_rules=[],
                should_block=False
            )

    def GetPreventionMode(self, request, context):
        return waf_pb2.PreventionModeResponse(enabled=self.prevention_mode)

    def SetPreventionMode(self, request, context):
        self.prevention_mode = request.enabled
        # Update MongoDB
        self.db.config.update_one(
            {'key': 'prevention_mode'},
            {'$set': {'enabled': request.enabled}},
            upsert=True
        )
        return waf_pb2.PreventionModeResponse(enabled=self.prevention_mode)

    def HealthCheck(self, request, context):
        return waf_pb2.HealthCheckResponse(is_healthy=True)

def serve():
    try:
        print("Starting server...")
        # Load SSL/TLS certificates
        with open('certs/server.key', 'rb') as f:
            private_key = f.read()
        with open('certs/server.crt', 'rb') as f:
            certificate_chain = f.read()
        with open('certs/ca.crt', 'rb') as f:
            root_certificates = f.read()
        print("Certificates loaded")

        server_credentials = grpc.ssl_server_credentials(
            [(private_key, certificate_chain)],
            root_certificates=root_certificates,
            require_client_auth=True
        )

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        waf_pb2_grpc.add_WAFServicer_to_server(WAFServicer(), server)
        
        server_address = '0.0.0.0:50051'
        server.add_secure_port(server_address, server_credentials)
        print("Server configured")

        server.start()
        print("Server started successfully")
        
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