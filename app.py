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
from pymongo import MongoClient  # Add this import

load_dotenv()


class IDSServicer(ids_pb2_grpc.IDSServicer):
    def __init__(self):
        mongo_user = quote_plus(os.getenv('MONGO_USER'))
        mongo_password = quote_plus(os.getenv('MONGO_PASSWORD'))
        mongo_port = os.getenv('MONGO_PORT')
        mongo_database = os.getenv('MONGO_DATABASE')

        mongo_url = f"mongodb://{mongo_user}:{mongo_password}@mongodb:{mongo_port}/{mongo_database}?authSource=admin"

        logger.info("Connecting to MongoDB...")
        logger.info(f"Database: {mongo_database}")
        
        # Initialize MongoDB client for logging
        try:
            self.mongo_client = MongoClient(mongo_url)
            self.db = self.mongo_client[mongo_database]
            
            # Explicitly create logs collection if it doesn't exist
            if 'logs' not in self.db.list_collection_names():
                logger.info("Creating logs collection...")
                self.db.create_collection('logs')
            else:
                logger.info("Logs collection already exists")
                
            # Test the connection with a simple operation
            self.db.logs.find_one()
            logger.info("Successfully connected to MongoDB")
            
        except Exception as e:
            logger.error(f"MongoDB connection error: {str(e)}")
            raise e

        # Initialize RuleEngine as before
        self.rule_engine = RuleEngine(mongo_url, 'ids_database', 'rules')
        self.rule_engine.load_rules()
        self.rule_engine.load_ml_model(
            model_path='models/model_info.joblib',
            vectorizer_path='models/vectorizer.joblib',
            preprocessor_path='models/preprocessor.joblib',
        )

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

            logger.info("=========== New Request Receieved =============")
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