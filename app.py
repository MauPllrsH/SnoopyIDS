import sys

import json
import grpc
import os
import sys
import gc
import traceback
import contextlib
import warnings
from dotenv import load_dotenv
from concurrent import futures
from utils.RuleEngine import RuleEngine
from urllib.parse import quote_plus
from datetime import datetime, timezone
import pytz
from pymongo import MongoClient
# Import scipy's entropy function to make it available globally
from scipy.stats import entropy

# Suppress warnings about regex match groups in str.contains()
warnings.filterwarnings('ignore', message=".*match groups.*", category=UserWarning)

# Import logger first so we can use it for startup logs
from utils.logger_config import logger

# Import the dockerfile_imports to ensure all necessary modules are available
try:
    import dockerfile_imports
    logger.info("Successfully imported dockerfile_imports for dependency checks")
except ImportError:
    logger.warn("dockerfile_imports module not found - will continue without it")

# Import WAF protocol buffers
try:
    import waf_pb2
    import waf_pb2_grpc
    logger.info("WAF protocol buffers imported successfully")
except ImportError as e:
    logger.error(f"Failed to import WAF protocol buffer modules: {str(e)}")
    logger.error("Make sure the WAF protocol buffers are compiled")
    raise

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

class IDSServicer(waf_pb2_grpc.WAFServicer):
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

            # Create whitelist collection if it doesn't exist
            if 'whitelist' not in collections:
                logger.info("Creating whitelist collection...")
                self.db.create_collection('whitelist')
                logger.info("Whitelist collection created")
                # Create indices for faster lookups
                self.db.whitelist.create_index([("method", 1), ("path", 1)])
            else:
                logger.info("Whitelist collection already exists")

            # Create graylist collection if it doesn't exist
            if 'graylist' not in collections:
                logger.info("Creating graylist collection...")
                self.db.create_collection('graylist')
                logger.info("Graylist collection created")
                # Create indices for faster lookups
                self.db.graylist.create_index([("method", 1), ("path", 1)])
            else:
                logger.info("Graylist collection already exists")

            # Create config collection if it doesn't exist
            if 'config' not in collections:
                logger.info("Creating config collection...")
                self.db.create_collection('config')
                logger.info("Config collection created")

                # Initialize prevention mode setting (default to disabled)
                self.db.config.insert_one({
                    'key': 'prevention_mode',
                    'enabled': False
                })
                logger.info("Prevention mode initialized to disabled")
            else:
                # Make sure prevention_mode config exists
                config = self.db.config.find_one({'key': 'prevention_mode'})
                if not config:
                    self.db.config.insert_one({
                        'key': 'prevention_mode',
                        'enabled': False
                    })
                    logger.info("Prevention mode config created (default: disabled)")
                else:
                    logger.info(f"Prevention mode config exists: {config['enabled']}")

            # Initialize RuleEngine (use same credentials but don't pass them directly)
            logger.info("Initializing RuleEngine...")
            self.rule_engine = RuleEngine(actual_mongo_url, mongo_database, 'blacklist')
            self.rule_engine.load_rules()
            logger.info("Rules loaded")

            # Load ML model components with much more robust error handling
            try:
                # First check what model files actually exist
                model_dir = 'model'
                standalone_path = os.path.join(model_dir, 'standalone_model.joblib')
                complete_package_path = os.path.join(model_dir, 'complete_model_package.joblib')
                model_info_path = os.path.join(model_dir, 'model_info.joblib')
                vectorizer_path = os.path.join(model_dir, 'vectorizer.joblib')
                preprocessor_path = os.path.join(model_dir, 'preprocessor.joblib')

                # Log what model files exist
                logger.info(f"Checking for model files:")
                logger.info(f"- standalone_model.joblib: {os.path.exists(standalone_path)}")
                logger.info(f"- complete_model_package.joblib: {os.path.exists(complete_package_path)}")
                logger.info(f"- model_info.joblib: {os.path.exists(model_info_path)}")
                logger.info(f"- vectorizer.joblib: {os.path.exists(vectorizer_path)}")
                logger.info(f"- preprocessor.joblib: {os.path.exists(preprocessor_path)}")

                # First try standalone model (best option)
                if os.path.exists(standalone_path):
                    logger.info(f"Loading standalone model from {standalone_path}")
                    try:
                        self.rule_engine.load_ml_model(model_path=standalone_path)
                        logger.info("Standalone model loaded successfully")
                    except Exception as e:
                        logger.error(f"Failed to load standalone model: {str(e)}")
                        logger.error(f"Error type: {type(e).__name__}")
                        logger.error(f"Error traceback: {traceback.format_exc()}")
                        # Continue to next option

                # Then try complete package
                elif os.path.exists(complete_package_path):
                    logger.info(f"Loading complete package from {complete_package_path}")
                    try:
                        self.rule_engine.load_ml_model(model_path=complete_package_path)
                        logger.info("Complete package loaded successfully")
                    except Exception as e:
                        logger.error(f"Failed to load complete package: {str(e)}")
                        logger.error(f"Error type: {type(e).__name__}")
                        logger.error(f"Error traceback: {traceback.format_exc()}")
                        # Continue to next option

                # Finally try individual components
                elif os.path.exists(model_info_path) and os.path.exists(vectorizer_path):
                    logger.info("Loading individual model components")
                    try:
                        self.rule_engine.load_ml_model(
                            model_path=model_info_path,
                            vectorizer_path=vectorizer_path,
                            preprocessor_path=preprocessor_path if os.path.exists(preprocessor_path) else None
                        )
                        logger.info("Individual components loaded successfully")
                    except Exception as e:
                        logger.error(f"Failed to load individual components: {str(e)}")
                        logger.error(f"Error type: {type(e).__name__}")
                        logger.error(f"Error traceback: {traceback.format_exc()}")

                else:
                    # No model files found
                    logger.error("No model files found in the model directory")
                    logger.error("Please ensure model files are copied to the correct location")
                    # Continue execution, but model_loaded will be False

            except Exception as ml_error:
                logger.error(f"Failed to load any ML model: {str(ml_error)}")
                logger.warning("System will fall back to rule-based detection only")

            # Verify the model was loaded correctly
            if hasattr(self.rule_engine, 'model_loaded') and self.rule_engine.model_loaded:
                logger.info("Model successfully loaded and ready for prediction")

                # Add the emergency prediction function to handle any feature count issues
                def emergency_predict(data, expected_features=82):
                    """Emergency prediction function that always produces correct feature count."""
                    import numpy as np

                    try:
                        logger.info(f"Using emergency prediction with {expected_features} features")

                        # Try to use the global standard_features function first
                        try:
                            import builtins
                            if hasattr(builtins, 'standard_features'):
                                features = builtins.standard_features(data, expected_features)
                                logger.info(f"Using global standard_features function: shape={features.shape}")
                            else:
                                # Fall back to loading the function from entropy module
                                try:
                                    import entropy
                                    features = entropy.standard_features(data, expected_features)
                                    logger.info(f"Using entropy.standard_features function: shape={features.shape}")
                                except (ImportError, AttributeError):
                                    # Fall back to simple zeros array
                                    features = np.zeros((1, expected_features))
                                    logger.warning("Using zeros array for features")
                        except Exception as feat_error:
                            logger.error(f"Error creating features: {str(feat_error)}")
                            features = np.zeros((1, expected_features))

                        # Make prediction
                        is_attack = False
                        confidence = 0.0

                        # Find the actual model with predict_proba
                        def find_actual_model(model_obj, depth=0):
                            if depth > 3:  # Limit recursion depth
                                return None

                            if hasattr(model_obj, 'predict_proba'):
                                return model_obj

                            if isinstance(model_obj, dict):
                                for key, value in model_obj.items():
                                    found = find_actual_model(value, depth + 1)
                                    if found:
                                        return found
                            return None

                        # Try to use the model directly
                        try:
                            # First try to find predict_proba in the model or nested dict
                            actual_model = find_actual_model(self.rule_engine.ml_model)

                            if actual_model:
                                probs = actual_model.predict_proba(features)
                                confidence = probs[0][1] if len(probs[0]) > 1 else probs[0][0]
                                # Get base threshold from rule engine
                                base_threshold = getattr(self.rule_engine, 'threshold', 0.55)
                                
                                # Apply higher threshold for POST requests
                                method = data.get('method', '')
                                threshold = base_threshold
                                if method == 'POST':
                                    threshold = 0.70  # Very high threshold for POST requests to prevent login issues
                                
                                is_attack = confidence > threshold
                                logger.info(
                                    f"Emergency prediction successful: {is_attack} (confidence: {confidence:.4f})")
                            else:
                                # If no model with predict_proba found, try simple prediction
                                model = self.rule_engine.ml_model
                                if hasattr(model, 'predict'):
                                    pred = model.predict(features)
                                    is_attack = bool(pred[0])
                                    confidence = 0.75 if is_attack else 0.25  # Default confidence
                                    logger.info(f"Basic prediction successful: {is_attack}")
                                else:
                                    logger.error("No suitable prediction method found in model")
                        except Exception as e:
                            logger.error(f"Emergency prediction failed: {str(e)}")

                        return is_attack, confidence
                    except Exception as e:
                        logger.error(f"Emergency prediction function error: {str(e)}")
                        return False, 0.0

                # Attach the emergency prediction function to the rule engine
                self.rule_engine.emergency_predict = emergency_predict
            else:
                logger.error("Model did not load correctly - prediction will not be available")

        except Exception as e:
            log_exception(e)
            raise e

    def get_prevention_mode(self):
        """Get the current prevention mode state from the database"""
        try:
            config = self.db.config.find_one({'key': 'prevention_mode'})
            if config:
                return config['enabled']
            return False
        except Exception as e:
            logger.error(f"Error getting prevention mode: {str(e)}")
            return False

    def set_prevention_mode(self, enabled):
        """Set the prevention mode state in the database"""
        try:
            result = self.db.config.update_one(
                {'key': 'prevention_mode'},
                {'$set': {'enabled': enabled}},
                upsert=True
            )
            logger.info(f"Prevention mode {'enabled' if enabled else 'disabled'}")
            return enabled
        except Exception as e:
            logger.error(f"Error setting prevention mode: {str(e)}")
            return False
            
    def check_whitelist(self, data):
        """Check if a request matches any whitelist entry"""
        try:
            # Extract basic request information
            method = data.get('method', '')
            path = data.get('path', '')
            query = data.get('query', '')
            body = data.get('body', '')
            ip = data.get('ip', '')
            
            # Log the whitelist check with appropriate detail
            log_message = f"Checking whitelist for {method} {path}"
            if query:
                query_preview = query[:30] + "..." if len(query) > 30 else query
                log_message += f" with query: {query_preview}"
            logger.debug(log_message)
            
            # First check for exact method + path + query pattern match
            whitelist_entries = list(self.db.whitelist.find({
                "method": method,
                "path": path,
                "query_pattern": {"$exists": True}
            }))
            
            # Check each entry that matches method and path but has a query pattern
            for entry in whitelist_entries:
                if entry.get('query_pattern'):
                    import re
                    # If the query matches the pattern
                    if re.match(entry['query_pattern'], query):
                        # Check additional patterns if needed
                        is_match = True
                        
                        if entry.get('body_pattern') and body:
                            if not re.match(entry['body_pattern'], body):
                                is_match = False
                                
                        if entry.get('ip_pattern') and ip:
                            if not re.match(entry['ip_pattern'], ip):
                                is_match = False
                                
                        if is_match:
                            logger.info(f"✅ Request matches whitelist with query pattern: {method} {path}")
                            return True
            
            # Then check for exact method and path match without query pattern
            # This is for entries that whitelist a path regardless of query
            whitelist_entry = self.db.whitelist.find_one({
                "method": method,
                "path": path,
                "query_pattern": {"$exists": False}
            })
            
            if whitelist_entry:
                # Check additional patterns if they exist
                is_match = True
                
                if whitelist_entry.get('body_pattern') and body:
                    import re
                    if not re.match(whitelist_entry['body_pattern'], body):
                        is_match = False
                        
                if whitelist_entry.get('ip_pattern') and ip:
                    import re
                    if not re.match(whitelist_entry['ip_pattern'], ip):
                        is_match = False
                
                if is_match:
                    logger.info(f"✅ Request matches whitelist (path only): {method} {path}")
                    return True
            
            # Check for pattern-based whitelist entries (more expensive, only if needed)
            # This handles cases where path has wildcards or regex patterns
            pattern_entries = list(self.db.whitelist.find({
                "method": method,
                "path_pattern": {"$exists": True}
            }))
            
            for entry in pattern_entries:
                import re
                if re.match(entry['path_pattern'], path):
                    # Check additional patterns
                    is_match = True
                    
                    if entry.get('query_pattern') and query:
                        if not re.match(entry['query_pattern'], query):
                            is_match = False
                            
                    if entry.get('body_pattern') and body:
                        if not re.match(entry['body_pattern'], body):
                            is_match = False
                            
                    if entry.get('ip_pattern') and ip:
                        if not re.match(entry['ip_pattern'], ip):
                            is_match = False
                    
                    if is_match:
                        logger.info(f"✅ Request matches pattern whitelist: {method} {path}")
                        return True
            
            # No whitelist match found
            return False
            
        except Exception as e:
            logger.error(f"Error checking whitelist: {str(e)}")
            # If there's an error, don't whitelist
            return False
            
    def check_graylist(self, data):
        """
        Check if a request matches graylist, update count, and possibly promote to whitelist.
        Returns: (is_in_graylist, should_block)
        """
        try:
            # Extract basic request information
            method = data.get('method', '')
            path = data.get('path', '')
            query = data.get('query', '')
            body = data.get('body', '')
            ip = data.get('ip', '')
            
            # Generate the same signature used in add_to_graylist
            # This ensures consistent matching
            signature = {
                "method": method,
                "path": path
            }
            
            # If query exists, include it in the signature
            if query:
                signature["query"] = query
            
            # For POST requests, include body hash in signature
            if method == "POST" and body and len(body) < 1000:
                import hashlib
                body_hash = hashlib.md5(body.encode()).hexdigest()
                signature["body_hash"] = body_hash
            
            # Query for exact signature match
            graylist_entry = self.db.graylist.find_one(signature)
            
            if graylist_entry:
                # Update the count and last_seen timestamp
                new_count = graylist_entry['count'] + 1
                promotion_threshold = graylist_entry.get('promotion_threshold', 10)
                
                # Update graylist entry
                from datetime import datetime, timezone
                
                self.db.graylist.update_one(
                    {"_id": graylist_entry['_id']},
                    {
                        "$set": {"last_seen": datetime.now(timezone.utc)},
                        "$inc": {"count": 1}
                    }
                )
                
                # Log with appropriate detail
                log_message = f"📋 Request matches graylist ({new_count}/{promotion_threshold}): {method} {path}"
                if "query" in signature:
                    query_preview = signature["query"][:30] + "..." if len(signature["query"]) > 30 else signature["query"]
                    log_message += f" with query: {query_preview}"
                if "body_hash" in signature:
                    log_message += f" with body hash: {signature['body_hash'][:8]}"
                    
                logger.info(log_message)
                
                # Check if we should promote to whitelist
                if new_count >= promotion_threshold:
                    logger.info(f"🔄 Promoting to whitelist: {method} {path}")
                    
                    # Create whitelist entry
                    # We use exact matching for promoted entries
                    whitelist_entry = {
                        "method": graylist_entry['method'],
                        "path": graylist_entry['path']
                    }
                    
                    # If the graylist entry had a query, create a query pattern for whitelist
                    if "query" in graylist_entry:
                        whitelist_entry["query_pattern"] = "^" + re.escape(graylist_entry["query"]) + "$"
                    
                    # Add metadata
                    whitelist_entry.update({
                        "added_at": datetime.now(timezone.utc),
                        "created_by": "auto-promotion",
                        "promoted_from_graylist": True
                    })
                    
                    # Add to whitelist
                    self.db.whitelist.insert_one(whitelist_entry)
                    
                    # Remove from graylist
                    self.db.graylist.delete_one({"_id": graylist_entry['_id']})
                
                # Return (is_in_graylist, should_block)
                return (True, False)
            
            # Not in graylist with this exact signature
            return (False, False)
            
        except Exception as e:
            logger.error(f"Error checking graylist: {str(e)}")
            # If there's an error checking graylist, don't consider it graylisted
            return (False, False)
    
    def add_to_graylist(self, data, promotion_threshold=10):
        """Add a request to the graylist for monitoring"""
        try:
            # Extract information for graylist entry
            method = data.get('method', '')
            path = data.get('path', '')
            query = data.get('query', '')
            body = data.get('body', '')
            
            # Generate a unique signature for the request
            # This ensures that each unique combination of method/path/query/body is treated as separate
            signature = {
                "method": method,
                "path": path
            }
            
            # If query or body exists, include them in the signature
            if query:
                signature["query"] = query
            
            # For POST requests, we may want to include the body in the signature
            # But we should be careful with large or changing bodies
            if method == "POST" and body and len(body) < 1000:  # Only include reasonably sized bodies
                import hashlib
                # Use a hash of the body rather than the full content
                body_hash = hashlib.md5(body.encode()).hexdigest()
                signature["body_hash"] = body_hash
            
            # Check if already in graylist with this exact signature
            existing = self.db.graylist.find_one(signature)
            
            if existing:
                logger.info(f"Request already in graylist: {method} {path} with query/body")
                return
                
            # Create graylist entry
            from datetime import datetime, timezone
            
            graylist_entry = signature.copy()  # Start with the signature
            
            # Add additional fields
            graylist_entry.update({
                "count": 1,
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "promotion_threshold": promotion_threshold
            })
            
            # Add to graylist
            self.db.graylist.insert_one(graylist_entry)
            
            # Log addition with appropriate detail
            log_message = f"Added to graylist: {method} {path}"
            if query:
                log_message += f" with query: {query[:30]}..." if len(query) > 30 else f" with query: {query}"
            if "body_hash" in graylist_entry:
                log_message += f" with body hash: {graylist_entry['body_hash'][:8]}"
                
            logger.info(log_message)
            
        except Exception as e:
            logger.error(f"Error adding to graylist: {str(e)}")

    def store_log_entry(self, analysis_data, is_attack, message, matched_rules=None, should_block=False):
        """Helper method to store log entries in MongoDB"""
        try:
            # Convert timestamp to Central Time
            try:
                # Parse the timestamp string to a datetime object
                # Handle both ISO format strings and datetime objects
                if isinstance(analysis_data['timestamp'], str):
                    # Try to parse as ISO format
                    timestamp_dt = datetime.fromisoformat(analysis_data['timestamp'].replace('Z', '+00:00'))
                else:
                    # Already a datetime object
                    timestamp_dt = analysis_data['timestamp']

                # Convert to Central Time
                central_tz = pytz.timezone('US/Central')
                if timestamp_dt.tzinfo is None:
                    # If timestamp has no timezone info, assume it's UTC
                    timestamp_dt = timestamp_dt.replace(tzinfo=timezone.utc)

                # Convert to Central Time
                central_time = timestamp_dt.astimezone(central_tz)

                # Format with timezone info
                formatted_timestamp = central_time.isoformat()
                logger.debug(f"Converted timestamp to Central Time: {formatted_timestamp}")
            except Exception as ts_error:
                logger.error(f"Error converting timestamp: {str(ts_error)}")
                # Use original timestamp if conversion fails
                formatted_timestamp = analysis_data['timestamp']

            log_entry = {
                'timestamp': formatted_timestamp,
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
                    'matched_rules': matched_rules if matched_rules else [],
                    'should_block': should_block
                }
            }
            result = self.db.logs.insert_one(log_entry)
            logger.debug(f"Log entry stored with ID: {result.inserted_id}")

        except Exception as e:
            logger.error(f"Failed to store log in MongoDB: {str(e)}")
            logger.exception("Full traceback:")
            raise e

    def ProcessLog(self, request, context):
        """Process incoming log requests with whitelist/graylist functionality."""
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

            # Check prevention mode status
            prevention_enabled = self.get_prevention_mode()

            # Enhanced request logging for debugging
            logger.warning("=========== New Request Received =============")
            logger.warning(f"METHOD: {request.method}")
            logger.warning(f"PATH: {path}")
            logger.warning(f"QUERY: {query}")
            logger.warning(f"PREVENTION MODE: {'ENABLED' if prevention_enabled else 'DISABLED'}")

            # Log body content with careful truncation
            body_log = request.body
            if body_log and len(body_log) > 500:
                body_log = body_log[:500] + " ... [TRUNCATED]"
            logger.warning(f"BODY: {body_log}")
            
            # WHITELIST CHECK - Skip all checks if whitelisted
            if self.check_whitelist(analysis_data):
                message = "Request whitelisted, bypassing checks"
                logger.info(f"⭐ WHITELISTED: {request.method} {path}")
                
                # Store log entry for whitelisted request
                self.store_log_entry(analysis_data, False, message, ["WHITELISTED"], False)
                
                return waf_pb2.ProcessResult(
                    injection_detected=False,
                    message=message,
                    matched_rules=["WHITELISTED"],
                    should_block=False
                )

            # GRAYLIST CHECK - Track but still process
            is_graylisted, _ = self.check_graylist(analysis_data)
            if is_graylisted:
                logger.info(f"📋 GRAYLISTED: {request.method} {path} (still checking)")
            
            # Check rules first
            matched_rule = self.rule_engine.check_rules(analysis_data)
            if matched_rule:
                message = f"⚠️  Rule '{matched_rule}' matched"
                logger.warning(f"🚨 Attack detected (Rule: {matched_rule})")
                logger.warning(f"Request: {request.method} {path}?{query}")
                logger.warning(f"Body: {request.body if request.body is not None else '<empty>'}")
                logger.warning(f"BLOCK REQUEST: {'YES' if prevention_enabled else 'NO (detection only)'}")

                # Store attack log
                self.store_log_entry(analysis_data, True, message, [matched_rule], prevention_enabled)

                return waf_pb2.ProcessResult(
                    injection_detected=True,
                    message=message,
                    matched_rules=[matched_rule],
                    should_block=prevention_enabled
                )

            # If no rule matches, use ML analysis
            try:
                try:
                    # Check if model is loaded before attempting prediction
                    if not self.rule_engine.model_loaded:
                        logger.warning("Cannot use ML prediction - model not loaded")
                        # Return as not an attack
                        is_anomaly, confidence = False, 0.0
                    else:
                        # Use ML prediction if model is loaded
                        logger.debug("Attempting ML prediction")
                        try:
                            is_anomaly, confidence = self.rule_engine.predict_anomaly(analysis_data)
                            logger.debug(f"ML prediction result: is_anomaly={is_anomaly}, confidence={confidence:.4f}")
                        except Exception as advanced_error:
                            # Log error
                            logger.error(f"Error in advanced prediction: {str(advanced_error)}")

                            # Try emergency prediction if available
                            if hasattr(self.rule_engine, 'emergency_predict'):
                                try:
                                    logger.warning("Attempting emergency prediction")
                                    is_anomaly, confidence = self.rule_engine.emergency_predict(analysis_data)
                                    logger.warning(
                                        f"Emergency prediction result: is_anomaly={is_anomaly}, confidence={confidence:.4f}")
                                except Exception as e:
                                    logger.error(f"Emergency prediction failed: {str(e)}")
                                    # Default to not an attack
                                    is_anomaly, confidence = False, 0.0
                            else:
                                # Default to not an attack
                                is_anomaly, confidence = False, 0.0
                                raise advanced_error  # Re-raise to be caught by outer catch
                except Exception as pred_error:
                    # Log but continue with non-attack result
                    logger.error(f"Error during ML prediction: {str(pred_error)}")
                    logger.error(f"Prediction error type: {type(pred_error).__name__}")
                    logger.error(f"Prediction error traceback: {traceback.format_exc()}")
                    # Default to not an attack
                    is_anomaly, confidence = False, 0.0
                if is_anomaly:
                    new_rule_name = self.rule_engine.generate_rule_from_anomaly(analysis_data)
                    message = f"🤖 ML model detected anomaly" + (
                        f". Generated rule: {new_rule_name}" if new_rule_name else "")

                    logger.warning(f"\n🚨 Attack detected (ML confidence: {confidence:.2f})")
                    logger.warning(f"Request: {request.method} {path}?{query}")
                    logger.warning(f"Body: {request.body if request.body is not None else '<empty>'}")
                    logger.warning(f"BLOCK REQUEST: {'YES' if prevention_enabled else 'NO (detection only)'}")
                    if new_rule_name:
                        logger.warning(f"Generated rule: {new_rule_name}")

                    # Store ML-detected attack log
                    self.store_log_entry(analysis_data, True, message,
                                         [new_rule_name] if new_rule_name else [],
                                         prevention_enabled)

                    return waf_pb2.ProcessResult(
                        injection_detected=True,
                        message=message,
                        matched_rules=[new_rule_name] if new_rule_name else [],
                        should_block=prevention_enabled
                    )
                else:
                    message = "No anomalies detected"
                    logger.info(f"✅ {request.method} {path}")

                    # Add to graylist if not already tracked
                    if not is_graylisted:
                        self.add_to_graylist(analysis_data)

                    # Store normal request log
                    self.store_log_entry(analysis_data, False, message, [], False)

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
                self.store_log_entry(analysis_data, False, message, [], False)

                return waf_pb2.ProcessResult(
                    injection_detected=False,
                    message=message,
                    matched_rules=[],
                    should_block=False
                )

        except Exception as e:
            message = f"Error processing request: {str(e)}"
            logger.error(f"Request processing error: {str(e)}")

            # Store error log if we have analysis_data
            if 'analysis_data' in locals():
                self.store_log_entry(analysis_data, False, message, [], False)

            return waf_pb2.ProcessResult(
                injection_detected=False,
                message=message,
                matched_rules=[],
                should_block=False
            )

    def HealthCheck(self, request, context):
        return waf_pb2.HealthCheckResponse(is_healthy=True)

    def GetPreventionMode(self, request, context):
        """Get the current prevention mode status"""
        try:
            enabled = self.get_prevention_mode()
            logger.info(f"Prevention mode status requested by {request.client_id}: {enabled}")
            return waf_pb2.PreventionModeResponse(enabled=enabled)
        except Exception as e:
            logger.error(f"Error in GetPreventionMode: {str(e)}")
            return waf_pb2.PreventionModeResponse(enabled=False)

    def SetPreventionMode(self, request, context):
        """Set the prevention mode status"""
        try:
            enabled = request.enabled
            result = self.set_prevention_mode(enabled)
            logger.info(f"Prevention mode set to {enabled} by {request.client_id}")
            return waf_pb2.PreventionModeResponse(enabled=result)
        except Exception as e:
            logger.error(f"Error in SetPreventionMode: {str(e)}")
            return waf_pb2.PreventionModeResponse(enabled=False)
            
    def AddToWhitelist(self, request, context):
        """Add an entry to the whitelist"""
        try:
            method = request.method
            path = request.path
            
            # Check if already exists
            existing = self.db.whitelist.find_one({
                "method": method,
                "path": path
            })
            
            if existing:
                logger.info(f"Path already in whitelist: {method} {path}")
                return waf_pb2.WhitelistResponse(
                    success=True,
                    message=f"Path already in whitelist: {method} {path}"
                )
                
            # Create whitelist entry
            from datetime import datetime, timezone
            
            whitelist_entry = {
                "method": method,
                "path": path,
                "query_pattern": request.query_pattern if request.query_pattern else None,
                "body_pattern": request.body_pattern if request.body_pattern else None,
                "ip_pattern": request.ip_pattern if request.ip_pattern else None,
                "added_at": datetime.now(timezone.utc),
                "created_by": request.client_id,
                "promoted_from_graylist": False
            }
            
            # Insert into whitelist
            result = self.db.whitelist.insert_one(whitelist_entry)
            logger.info(f"Added to whitelist: {method} {path} (ID: {result.inserted_id})")
            
            # Also remove from graylist if it exists there
            self.db.graylist.delete_one({
                "method": method,
                "path": path
            })
            
            return waf_pb2.WhitelistResponse(
                success=True,
                message=f"Successfully added to whitelist: {method} {path}"
            )
            
        except Exception as e:
            error_msg = f"Error adding to whitelist: {str(e)}"
            logger.error(error_msg)
            return waf_pb2.WhitelistResponse(
                success=False,
                message=error_msg
            )
            
    def RemoveFromWhitelist(self, request, context):
        """Remove an entry from the whitelist"""
        try:
            method = request.method
            path = request.path
            
            # Delete from whitelist
            result = self.db.whitelist.delete_one({
                "method": method,
                "path": path
            })
            
            if result.deleted_count > 0:
                logger.info(f"Removed from whitelist: {method} {path}")
                return waf_pb2.WhitelistResponse(
                    success=True,
                    message=f"Successfully removed from whitelist: {method} {path}"
                )
            else:
                logger.info(f"Path not found in whitelist: {method} {path}")
                return waf_pb2.WhitelistResponse(
                    success=False,
                    message=f"Path not found in whitelist: {method} {path}"
                )
                
        except Exception as e:
            error_msg = f"Error removing from whitelist: {str(e)}"
            logger.error(error_msg)
            return waf_pb2.WhitelistResponse(
                success=False,
                message=error_msg
            )
            
    def GetWhitelistedPaths(self, request, context):
        """Get all whitelisted paths"""
        try:
            whitelist_entries = list(self.db.whitelist.find({}))
            paths = []
            
            for entry in whitelist_entries:
                paths.append(waf_pb2.PathEntry(
                    method=entry.get('method', ''),
                    path=entry.get('path', ''),
                    query_pattern=entry.get('query_pattern', ''),
                    body_pattern=entry.get('body_pattern', ''),
                    ip_pattern=entry.get('ip_pattern', ''),
                    added_at=str(entry.get('added_at', '')),
                    created_by=entry.get('created_by', '')
                ))
                
            return waf_pb2.PathListResponse(
                success=True,
                message=f"Found {len(paths)} whitelisted paths",
                paths=paths
            )
            
        except Exception as e:
            error_msg = f"Error getting whitelisted paths: {str(e)}"
            logger.error(error_msg)
            return waf_pb2.PathListResponse(
                success=False,
                message=error_msg,
                paths=[]
            )
            
    def GetGraylistedPaths(self, request, context):
        """Get all graylisted paths"""
        try:
            graylist_entries = list(self.db.graylist.find({}))
            paths = []
            
            for entry in graylist_entries:
                paths.append(waf_pb2.GraylistEntry(
                    method=entry.get('method', ''),
                    path=entry.get('path', ''),
                    query_pattern=entry.get('query_pattern', ''),
                    body_pattern=entry.get('body_pattern', ''),
                    ip_pattern=entry.get('ip_pattern', ''),
                    count=entry.get('count', 0),
                    first_seen=str(entry.get('first_seen', '')),
                    last_seen=str(entry.get('last_seen', '')),
                    promotion_threshold=entry.get('promotion_threshold', 10)
                ))
                
            return waf_pb2.GraylistResponse(
                success=True,
                message=f"Found {len(paths)} graylisted paths",
                entries=paths
            )
            
        except Exception as e:
            error_msg = f"Error getting graylisted paths: {str(e)}"
            logger.error(error_msg)
            return waf_pb2.GraylistResponse(
                success=False,
                message=error_msg,
                entries=[]
            )

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
        waf_pb2_grpc.add_WAFServicer_to_server(IDSServicer(), server)
        
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