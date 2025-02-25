import re
import pandas as pd
import numpy as np
from scipy.sparse import issparse
import joblib
from pymongo import MongoClient
from bson.objectid import ObjectId
from utils.logger_config import logger
import os

from utils.Rule import Rule

# Pre-compile regex patterns for better performance
SQL_PATTERN = re.compile(r'select|from|where|union|insert|update|delete|drop|exec|system', re.IGNORECASE)
SCRIPT_PATTERN = re.compile(r'<script|javascript:|data:|alert\(|eval\(|setTimeout|setInterval', re.IGNORECASE)
DANGEROUS_URL_PATTERN = re.compile(r'evil\.com|file://|http://|https://|ftp://|\/etc\/|\/var\/|\/root\/|\.\.\/|\%[0-9a-fA-F]{2}', re.IGNORECASE)
FORMAT_STRING_PATTERN = re.compile(r'\%[0-9]*[xsdfo]|\%n|\%p|\%x|\%d', re.IGNORECASE)


class RuleEngine:
    def __init__(self, mongo_uri, db_name, collection_name):
        # Set up MongoDB with connection pooling and timeouts
        self.client = MongoClient(
            mongo_uri,
            connectTimeoutMS=5000,
            serverSelectionTimeoutMS=5000,
            maxPoolSize=10
        )
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.rules = []
        self.ml_model = None
        self.vectorizer = None
        self.preprocessor = None
        self.label_encoder = None
        
        # Track model state
        self.model_loaded = False
        self.standalone_mode = False
        self.predict_function = None
        self.feature_names = []
        self.iso_model = None
        self.threshold = 0.5
        self.iso_weight = 0.3

    def load_rules(self):
        self.rules = []
        for rule_doc in self.collection.find():
            self.rules.append(Rule(
                str(rule_doc['_id']),
                rule_doc['name'],
                rule_doc['pattern'],
                rule_doc['field']
            ))

    def check_rules(self, data):
        for rule in self.rules:
            if rule.check(data):
                return rule.name
        return None

    def add_rule(self, name, pattern, field):
        rule_doc = {
            'name': name,
            'pattern': pattern,
            'field': field
        }
        result = self.collection.insert_one(rule_doc)
        self.load_rules()
        return str(result.inserted_id)

    def update_rule(self, rule_id, name, pattern, field):
        self.collection.update_one(
            {'_id': ObjectId(rule_id)},
            {'$set': {'name': name, 'pattern': pattern, 'field': field}}
        )
        self.load_rules()

    def delete_rule(self, rule_id):
        self.collection.delete_one({'_id': ObjectId(rule_id)})
        self.load_rules()

    def load_ml_model(self, model_path, vectorizer_path=None, preprocessor_path=None):
        """Load ML model components with proper validation and error handling"""
        try:
            # First check if the path itself is the standalone model
            if 'standalone_model.joblib' in model_path:
                standalone_path = model_path
                logger.info(f"Using provided standalone model: {standalone_path}")
            else:
                # Otherwise check for standalone model in the same directory
                standalone_path = os.path.join(os.path.dirname(model_path), 'standalone_model.joblib')
                if os.path.exists(standalone_path):
                    logger.info(f"Found standalone model package in directory: {standalone_path}")
                else:
                    # No standalone model found
                    standalone_path = None
                    
            # Try to load the standalone package if found
            if standalone_path and os.path.exists(standalone_path):
                try:
                    # Load the package
                    package = joblib.load(standalone_path)
                    
                    # Extract model components
                    self.ml_model = package.get('model')
                    self.iso_model = package.get('iso_model')
                    self.vectorizer = package.get('vectorizer')
                    self.preprocessor = package.get('preprocessor')
                    self.feature_names = package.get('feature_names', [])
                    self.threshold = package.get('threshold', 0.5)
                    self.iso_weight = package.get('iso_weight', 0.3)
                    
                    # Store the code and prediction function for direct execution
                    self.standalone_code = package.get('code', '')
                    self.predict_function_name = package.get('predict_function', '')
                    
                    # Dynamically load the prediction function
                    if self.standalone_code and self.predict_function_name:
                        # Create a namespace for the code with required imports
                        namespace = {}
                        try:
                            # Pre-import required libraries to make them available to the code
                            import pandas as pd
                            import numpy as np
                            import re
                            import os
                            import sys
                            from scipy.sparse import issparse
                            
                            # Add these to the namespace
                            namespace['pd'] = pd
                            namespace['np'] = np
                            namespace['re'] = re
                            namespace['os'] = os
                            namespace['sys'] = sys
                            namespace['issparse'] = issparse
                            namespace['pandas'] = pd
                            namespace['numpy'] = np
                            
                            # Execute the code in the namespace
                            exec(self.standalone_code, namespace)
                            
                            # Get the prediction function
                            self.predict_function = namespace.get(self.predict_function_name)
                            if self.predict_function:
                                logger.info("Successfully loaded standalone prediction function")
                            else:
                                logger.warning(f"Prediction function '{self.predict_function_name}' not found in code")
                        except Exception as code_error:
                            logger.error(f"Error loading prediction code: {str(code_error)}")
                    
                    # Mark model as successfully loaded
                    self.model_loaded = True
                    self.standalone_mode = True
                    logger.info("Standalone model package loaded successfully")
                    
                    # Early return, we have everything we need
                    return
                except Exception as standalone_error:
                    logger.error(f"Error loading standalone model: {str(standalone_error)}")
                    logger.warning("Falling back to other model formats")
                    # Initialize to prevent errors
                    self.model_loaded = False
                    self.standalone_mode = False
            
            # Check if we have a combined model package (second best option)
            if os.path.exists(model_path) and ('complete_model_package' in model_path or 'model_dir' in model_path):
                # Load the complete model package
                logger.info(f"Loading complete model package from {model_path}")
                package = joblib.load(model_path)
                
                # Extract components from package
                self.ml_model = package.get('model')
                self.iso_model = package.get('iso_model')
                self.vectorizer = package.get('vectorizer')
                self.preprocessor = package.get('preprocessor')
                self.feature_names = package.get('feature_names', [])
                self.onehot_encoder = package.get('onehot_encoder')
                self.threshold = package.get('threshold', 0.5)
                self.iso_weight = package.get('iso_weight', 0.3)
                
                logger.info("Complete model package loaded successfully")
                self.model_loaded = True
                self.standalone_mode = False
                return
            
            # Fall back to individual files if package not available
            logger.info("Complete package not found, attempting to load individual components")
            
            # Check if files exist before loading
            for path in [model_path, vectorizer_path]:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"Model file not found: {path}")
            if preprocessor_path and not os.path.exists(preprocessor_path):
                raise FileNotFoundError(f"Preprocessor file not found: {preprocessor_path}")
                
            # Load model info first
            model_info = joblib.load(model_path)
            if not isinstance(model_info, dict) or 'model' not in model_info:
                raise ValueError(f"Invalid model format in {model_path}")
                
            self.ml_model = model_info['model']
            self.n_features = model_info.get('n_features', 0)
            self.feature_names = model_info.get('feature_names', [])

            # Load vectorizer
            self.vectorizer = joblib.load(vectorizer_path)

            # Load preprocessor if available
            if preprocessor_path:
                self.preprocessor = joblib.load(preprocessor_path)
                if hasattr(self.preprocessor, 'named_transformers_') and 'cat' in self.preprocessor.named_transformers_:
                    logger.debug(f"Method values in training: {self.preprocessor.named_transformers_['cat'].categories_}")
            
            # Mark model as successfully loaded
            self.model_loaded = True
            self.standalone_mode = False
            logger.info("ML model components loaded successfully")

        except Exception as e:
            logger.error(f"Error loading model components: {str(e)}")
            # Make sure these are initialized
            if not hasattr(self, 'model_loaded'):
                self.model_loaded = False
            if not hasattr(self, 'standalone_mode'):
                self.standalone_mode = False
            # Set to false regardless
            self.model_loaded = False
            self.standalone_mode = False
            raise ValueError(f"Failed to load ML model: {str(e)}")

    def extract_features(self, data):
        """
        Extract features using Cicada's feature extractor for consistency.
        
        This method is kept for backward compatibility, but we'll forward
        to the more advanced feature extractor from Cicada.
        """
        try:
            # Import Cicada's feature extractor dynamically
            from utils.cicada.feature_extractor import extract_features as cicada_extract_features
            
            # Convert single request to DataFrame
            df = pd.DataFrame([data])
            
            # Use Cicada's advanced feature extraction
            logger.debug("Using Cicada's advanced feature extraction")
            features = cicada_extract_features(df)
            
            # Manually add endpoint features that might be missing (for Docker environment)
            # These match what Cicada's feature_alignment.py would normally add
            features['is_search_endpoint'] = df['path'].str.contains('/search').astype(int)
            features['is_login_endpoint'] = df['path'].str.contains('/login').astype(int)
            features['is_root_endpoint'] = (df['path'] == '/').astype(int)
            features['path_length'] = df['path'].str.len()
            features['query_param_count'] = df['query'].str.count('&') + 1
            features['has_special_chars'] = df['path'].str.contains('[<>{}()\'"]').astype(int)
            
            return features
        except Exception as e:
            logger.error(f"Error using Cicada's feature extractor: {str(e)}")
            logger.warning("Falling back to original feature extraction")
            
            # Fall back to original feature extraction if there's an error
            df = pd.DataFrame([data])
            features = pd.DataFrame({
                'method': df['method'],
                'has_body': df['body'].notna().astype(int),
                'header_count': df['headers'].apply(lambda x: len(x) if isinstance(x, dict) else 0),
                'has_query': df['query'].astype(str).str.len().gt(0).astype(int),
                'content_type': df['headers'].apply(lambda x: 1 if 'content-type' in str(x).lower() else 0),
                'user_agent': df['headers'].apply(lambda x: 1 if 'user-agent' in str(x).lower() else 0),
                'body_length': df['body'].fillna('').astype(str).str.len(),
                'path_depth': df['path'].str.count('/'),
                'has_sql_keywords': (
                        df['body'].fillna('').astype(str).str.lower().str.contains(SQL_PATTERN) |
                        df['query'].fillna('').astype(str).str.lower().str.contains(SQL_PATTERN)
                ).astype(int),
                'has_script_tags': (
                        df['body'].fillna('').astype(str).str.lower().str.contains(SCRIPT_PATTERN) |
                        df['query'].fillna('').astype(str).str.lower().str.contains(SCRIPT_PATTERN) |
                        df['query'].fillna('').astype(str).str.lower().str.contains(DANGEROUS_URL_PATTERN) |
                        df['query'].fillna('').astype(str).str.lower().str.contains(FORMAT_STRING_PATTERN)
                ).astype(int)
            })
            return features

    def predict_anomaly(self, data):
        """Predict if request is anomalous with proper error handling."""
        if not self.model_loaded:
            logger.warning("ML model not loaded, cannot perform prediction")
            raise ValueError("ML model components are not loaded properly")

        # Check if we're in standalone mode (using self-contained model)
        if hasattr(self, 'standalone_mode') and self.standalone_mode and hasattr(self, 'predict_function'):
            try:
                # Use the standalone prediction function directly
                logger.debug("Using standalone prediction function")
                
                # Create a model_components dictionary with all needed components
                
                # Function to recursively find the actual model in nested dictionaries
                def find_actual_model(model_obj, depth=0):
                    if depth > 3:  # Limit recursion depth
                        return model_obj
                        
                    if isinstance(model_obj, dict):
                        # Try common keys for models
                        for key in ['model', 'ensemble_model', 'ml_model', 'classifier']:
                            if key in model_obj:
                                found = find_actual_model(model_obj[key], depth+1)
                                if hasattr(found, 'predict_proba'):
                                    logger.debug(f"Found model at key '{key}'")
                                    return found
                        
                        # If we reach here, no model was found in known keys
                        # Try to find any dict value that has predict_proba
                        for key, value in model_obj.items():
                            if hasattr(value, 'predict_proba'):
                                logger.debug(f"Found model at key '{key}'")
                                return value
                                
                    return model_obj
                
                # Find the actual model in potentially nested structures
                actual_model = find_actual_model(self.ml_model)
                if hasattr(actual_model, 'predict_proba'):
                    logger.debug(f"Found usable model of type {type(actual_model).__name__}")
                else:
                    logger.warning(f"Could not find usable model, using {type(actual_model).__name__}")
                
                model_components = {
                    'model': actual_model,  # Use actual model, not the wrapper dict
                    'iso_model': getattr(self, 'iso_model', None),
                    'vectorizer': self.vectorizer,
                    'preprocessor': self.preprocessor,
                    'feature_names': getattr(self, 'feature_names', []),
                    'threshold': getattr(self, 'threshold', 0.5),
                    'iso_weight': getattr(self, 'iso_weight', 0.3)
                }
                
                # Check if components are valid before prediction
                if (hasattr(actual_model, 'predict_proba') and
                    self.vectorizer is not None and
                    self.preprocessor is not None):
                    logger.debug("Verified model components for standalone prediction")
                else:
                    logger.warning("Model components validation failed - prediction may not work correctly")
                    if not hasattr(actual_model, 'predict_proba'):
                        logger.error(f"Model type {type(actual_model)} does not support predict_proba")
                    if self.vectorizer is None:
                        logger.error("Vectorizer is missing")
                    if self.preprocessor is None:
                        logger.error("Preprocessor is missing")
                
                # Make sure pandas is available
                try:
                    import pandas as pd
                    import numpy as np
                    import re
                    from scipy.sparse import issparse
                except ImportError as e:
                    logger.error(f"Required library not available: {str(e)}")
                    # Fall back to simple rule-based detection
                    raise ImportError(f"Required import not available: {str(e)}")
                
                # Make DataFrame if needed
                if isinstance(data, dict):
                    data_df = pd.DataFrame([data])
                else:
                    data_df = data
                
                # Call the standalone prediction function
                try:
                    # Try using the standalone function first
                    is_attack, confidence = self.predict_function(data_df, model_components)
                    logger.debug(f"Standalone prediction: {is_attack} with confidence {confidence:.4f}")
                    return is_attack, confidence
                except Exception as e:
                    logger.error(f"Error in standalone prediction: {str(e)}")
                    logger.warning("Trying built-in prediction as fallback")
                    
                    try:
                        # Direct prediction using model components
                        if hasattr(actual_model, 'predict_proba'):
                            # Extract basic features
                            X = self.extract_features(data)
                            
                            # Make sure vectorizer works
                            if hasattr(self.vectorizer, 'transform'):
                                path_features = self.vectorizer.transform([data.get('path', '')])
                                
                                # Try to preprocess features
                                if hasattr(self.preprocessor, 'transform'):
                                    X_preprocessed = self.preprocessor.transform(X)
                                    
                                    # Combine features
                                    if issparse(X_preprocessed):
                                        X_preprocessed = X_preprocessed.toarray()
                                    if issparse(path_features):
                                        path_features = path_features.toarray()
                                        
                                    X_combined = np.hstack((X_preprocessed, path_features))
                                    
                                    # Make prediction
                                    probs = actual_model.predict_proba(X_combined)
                                    if len(probs[0]) > 1:
                                        confidence = probs[0][1]  # Binary classification
                                    else:
                                        confidence = probs[0][0]
                                        
                                    threshold = getattr(self, 'threshold', 0.5)
                                    is_attack = confidence > threshold
                                    
                                    logger.debug(f"Direct prediction: {is_attack} with confidence {confidence:.4f}")
                                    return is_attack, confidence
                    except Exception as direct_error:
                        logger.error(f"Direct prediction failed: {str(direct_error)}")
                
                    # If we reach here, both prediction methods failed
                    logger.error("All prediction methods failed - returning default (safe) value")
                    return False, 0.0
                
            except Exception as standalone_error:
                # Log the error but continue with fallback methods
                logger.error(f"Error using standalone prediction: {str(standalone_error)}")
                logger.warning("Falling back to standard prediction methods")
        
        # Standard prediction methods if standalone mode fails or is not available
        try:
            # First try the enhanced feature alignment approach (Cicada compatibility)
            try:
                # Import feature alignment utility from Cicada
                from utils.cicada.feature_alignment import extract_features_consistent
                
                # Convert single request to DataFrame for compatibility
                df = pd.DataFrame([data])
                
                # Use the consistent feature extraction that matches training
                logger.debug("Using Cicada's feature alignment for prediction")
                try:
                    X_combined = extract_features_consistent(
                        df, 
                        self.vectorizer, 
                        self.preprocessor, 
                        self.feature_names if hasattr(self, 'feature_names') else [],
                        getattr(self, 'onehot_encoder', None)
                    )
                except Exception as e:
                    if "columns are missing" in str(e):
                        # Handle missing columns error by using direct approach
                        logger.warning(f"Feature alignment error: {str(e)}")
                        logger.warning("Falling back to direct feature extraction and transformation")
                        
                        # Extract features using our enhanced extract_features method that adds endpoint features
                        X = self.extract_features(data)
                        
                        # Transform features manually
                        categorical_columns = ['method']
                        numerical_columns = [col for col in X.columns if col not in categorical_columns]
                        
                        # Get onehot encoder from preprocessor
                        onehot = getattr(self, 'onehot_encoder', None)
                        if onehot is None and hasattr(self.preprocessor, 'named_transformers_'):
                            try:
                                onehot = self.preprocessor.named_transformers_['cat']
                            except:
                                pass
                        
                        if onehot:
                            X_cat = onehot.transform(X[categorical_columns])
                        else:
                            # If we can't get the encoder, use a simple one-hot encoding
                            from sklearn.preprocessing import OneHotEncoder
                            temp_encoder = OneHotEncoder(handle_unknown='ignore')
                            X_cat = temp_encoder.fit_transform(X[categorical_columns])
                            
                        # Transform numerical features    
                        X_num = self.preprocessor.named_transformers_['num'].transform(X[numerical_columns])
                        
                        # Convert to arrays if they're sparse
                        if issparse(X_num):
                            X_num = X_num.toarray()
                        if issparse(X_cat):
                            X_cat = X_cat.toarray()
                            
                        # Get path features
                        path_features = self.vectorizer.transform(df['path'])
                        if issparse(path_features):
                            path_features = path_features.toarray()
                            
                        # Combine features
                        X_combined = np.hstack((X_num, X_cat, path_features))
                    else:
                        # Re-raise other exceptions
                        raise
                
                # Check if we have an isolation forest model for anomaly boosting
                if hasattr(self, 'iso_model') and self.iso_model is not None:
                    # Import the anomaly boosting utility
                    from utils.cicada.anomaly_boosting import anomaly_boosted_predict
                    
                    # Use advanced anomaly-boosted prediction
                    logger.debug("Using anomaly-boosted prediction")
                    threshold = getattr(self, 'threshold', 0.5)
                    iso_weight = getattr(self, 'iso_weight', 0.3)
                    
                    # Get anomaly-boosted prediction
                    _, attack_probabilities = anomaly_boosted_predict(
                        self.ml_model, X_combined, self.iso_model, 
                        threshold=threshold, 
                        iso_weight=iso_weight
                    )
                    attack_probability = attack_probabilities[0]
                    
                    logger.debug(f"Anomaly-boosted probability: {attack_probability:.4f}, threshold: {threshold}")
                    return attack_probability > threshold, attack_probability
                else:
                    # Standard prediction with the ensemble model
                    prediction_proba = self.ml_model.predict_proba(X_combined)
                    attack_probability = prediction_proba[0][1]
                    
                    # Use the optimal threshold from Cicada if available
                    threshold = getattr(self, 'threshold', 0.5)
                    
                    logger.debug(f"Prediction probability: {attack_probability:.4f}, threshold: {threshold}")
                    return attack_probability > threshold, attack_probability
                
            except Exception as feature_align_error:
                # Log the error but continue with fallback
                logger.error(f"Error using Cicada feature alignment: {str(feature_align_error)}")
                logger.warning("Falling back to original prediction method")
                
                # Fall back to original approach
                raise feature_align_error
                
        except Exception:
            # Fall back to original prediction approach
            try:
                # Extract features using original method
                X = self.extract_features(data)
                path_features = self.vectorizer.transform([data.get('path', '')])

                if self.preprocessor:
                    # Transform features through preprocessor
                    X_preprocessed = self.preprocessor.transform(X)

                    # Convert sparse matrices to arrays if needed
                    if issparse(X_preprocessed):
                        X_preprocessed = X_preprocessed.toarray()
                    if issparse(path_features):
                        path_features = path_features.toarray()

                    # Combine features
                    X_combined = np.hstack((X_preprocessed, path_features))
                    
                    # Make prediction
                    prediction_proba = self.ml_model.predict_proba(X_combined)
                    attack_probability = prediction_proba[0][1]

                    # Determine threshold based on request properties
                    has_query = X['has_query'].iloc[0] == 1
                    has_suspicious_content = (X['has_sql_keywords'].iloc[0] == 1 or
                                            X['has_script_tags'].iloc[0] == 1)
                    threshold = 0.3 if (has_query or has_suspicious_content) else 0.5

                    logger.debug(f"Prediction probability (fallback): {attack_probability:.4f}, threshold: {threshold}")
                    return attack_probability > threshold, attack_probability

                else:
                    raise ValueError("Preprocessor not loaded")
                    
            except Exception as e:
                logger.error(f"Error during anomaly prediction: {str(e)}")
                # False alarm is better than a crash in production
                logger.error("Returning False due to error - REQUEST MAY BE MISSED")
                return False, 0.0

    def generate_rule_from_anomaly(self, data):
        """Generate rules based purely on ML model's detection with improved validation."""
        if not self.model_loaded:
            logger.warning("ML model not loaded, cannot generate rules")
            return None
            
        try:
            # Get ML features and vectorizer information
            features = self.extract_features(data)
            path = data.get('path', '')
            query = data.get('query', '')
            body = data.get('body', '')

            logger.info(f"Generating rules for detected attack - Path: {path}, Query: {query}")
            rules_to_generate = []
            
            # Rate limit rule generation to avoid DoS via rule table
            max_rules = 5000  # Set a reasonable limit
            if len(self.rules) >= max_rules:
                logger.warning(f"Maximum rule limit reached ({max_rules}). Not generating new rules")
                return None

            # If query parameters exist and contributed to detection, create a query rule
            if query and features['has_query'].iloc[0] == 1:
                # Only generate rule if it contains suspicious patterns
                if (SQL_PATTERN.search(query) or 
                    SCRIPT_PATTERN.search(query) or 
                    DANGEROUS_URL_PATTERN.search(query)):
                    
                    # Create pattern from the actual query that triggered detection
                    query_pattern = re.escape(query)  # Escape special characters
                    rules_to_generate.append(('query', query_pattern))
                    logger.info(f"Generated query pattern: {query_pattern}")

            # Create path rule based on vectorizer features
            path_features = self.vectorizer.transform([path])
            if path_features.getnnz() > 0:
                # Get the parts of the path that triggered ML detection
                feature_indices = path_features.nonzero()[1]
                if len(feature_indices) > 0:
                    # Use a more specific pattern to avoid overly broad rules
                    path_pattern = self.extract_pattern_from_path(path)
                    if path_pattern:
                        rules_to_generate.append(('path', path_pattern))
                        logger.info(f"Generated path pattern: {path_pattern}")
            
            # Check body if it might contain attacks
            if body and features['has_sql_keywords'].iloc[0] == 1 or features['has_script_tags'].iloc[0] == 1:
                body_pattern = self.extract_pattern_from_content(body)
                if body_pattern:
                    rules_to_generate.append(('body', body_pattern))
                    logger.info(f"Generated body pattern: {body_pattern}")

            # Create and store rules
            created_rules = []
            for field, pattern in rules_to_generate:
                # Verify pattern is not empty and not too broad
                if pattern and len(pattern) > 3:
                    name = f"ML_Generated_Rule_{field}_{len(self.rules)}"
                    logger.info(f"Creating new rule - Name: {name}, Field: {field}, Pattern: {pattern}")
                    
                    # Check if similar rule already exists
                    exists = any(r.field == field and r.pattern == pattern for r in self.rules)
                    if not exists:
                        rule_id = self.add_rule(
                            name=name,
                            pattern=pattern,
                            field=field
                        )
                        created_rules.append(name)
                    else:
                        logger.info(f"Similar rule already exists, skipping")

            return created_rules[0] if created_rules else None

        except Exception as e:
            logger.error(f"Error generating rules from anomaly: {str(e)}")
            return None

    def extract_pattern_from_content(self, *contents, base_pattern=None):
        """Extract patterns from content that matched ML features."""
        # If no base_pattern is provided, use a default pattern for suspicious content
        if base_pattern is None:
            base_pattern = r'(?:' + SQL_PATTERN.pattern + r')|(?:' + SCRIPT_PATTERN.pattern + r')'
            compiled_pattern = re.compile(base_pattern, re.IGNORECASE)
        else:
            # Compile the provided pattern if it's a string
            if isinstance(base_pattern, str):
                compiled_pattern = re.compile(base_pattern, re.IGNORECASE)
            else:
                # Assume it's already a compiled pattern
                compiled_pattern = base_pattern
                
        for content in contents:
            if not content:
                continue
                
            content = str(content).lower()
            match = compiled_pattern.search(content)
            
            if match:
                # Extract the matched pattern and its immediate context
                start = max(0, match.start() - 10)
                end = min(len(content), match.end() + 10)
                context = content[start:end]
                # Escape special characters but keep the pattern structure
                return re.escape(context).replace('\\s+', '\\s+')
                
        return None

    def extract_pattern_from_path(self, path):
        """Extract suspicious patterns from path based on ML vectorizer."""
        if not path:
            return None

        # Get the most important path segments according to vectorizer
        path_features = self.vectorizer.transform([path])
        if path_features.getnnz() == 0:
            return None

        # Get feature names that were activated
        feature_indices = path_features.nonzero()[1]
        if len(feature_indices) == 0:
            return None

        important_features = [self.feature_names[i] for i in feature_indices]

        # Create a pattern that matches the path structure
        path_parts = path.split('/')
        pattern_parts = []

        # At least one part must contain a suspicious feature to create a rule
        found_suspicious = False

        for part in path_parts:
            if any(feature in part.lower() for feature in important_features):
                pattern_parts.append(re.escape(part))
                found_suspicious = True
            else:
                # Only use wildcard for non-suspicious parts if we found a suspicious part
                pattern_parts.append('[^/]+' if found_suspicious else re.escape(part))

        # Don't create a rule if no suspicious parts were found
        if not found_suspicious:
            return None

        final_pattern = '/'.join(pattern_parts)

        # Don't create overly general patterns
        if final_pattern in ['[^/]+/[^/]+', '/']:
            return None

        return final_pattern
