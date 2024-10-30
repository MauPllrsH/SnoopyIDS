import json
import re
import pandas as pd
import numpy as np
from scipy.sparse import issparse
import joblib
from pymongo import MongoClient
from bson.objectid import ObjectId
from utils.logger_config import logger

from utils.Rule import Rule
from utils.CustomLabelEncoder import CustomLabelEncoder



class RuleEngine:
    def __init__(self, mongo_uri, db_name, collection_name):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.rules = []
        self.ml_model = None
        self.vectorizer = None
        self.preprocessor = None
        self.label_encoder = None

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

    def load_ml_model(self, model_path, vectorizer_path, preprocessor_path=None, label_encoder_path=None):
        try:
            # Load model info first
            model_info = joblib.load(model_path)
            self.ml_model = model_info['model']
            self.n_features = model_info['n_features']
            self.feature_names = model_info['feature_names']

            # Load vectorizer
            self.vectorizer = joblib.load(vectorizer_path)

            # Load preprocessor if available
            if preprocessor_path:
                self.preprocessor = joblib.load(preprocessor_path)
                print("Method values in training:", self.preprocessor.named_transformers_['cat'].categories_)

        except Exception as e:
            print(f"Error loading model components: {str(e)}")
            raise

    def extract_features(self, data):
        # Convert single request to DataFrame
        df = pd.DataFrame([data])
        logger.info(f"Input data for feature extraction: {json.dumps(data, indent=2)}")
        logger.info(f"Input path: {data.get('path', '')}")
        logger.info(f"Input query: {data.get('query', '')}")

        # Enhanced attack detection patterns
        sql_pattern = r'select|from|where|union|insert|update|delete|drop|exec|system'
        script_pattern = r'<script|javascript:|data:|alert\(|eval\(|setTimeout|setInterval'
        dangerous_url_pattern = r'evil\.com|file://|http://|https://|ftp://|\/etc\/|\/var\/|\/root\/|\.\.\/|\%[0-9a-fA-F]{2}'
        format_string_pattern = r'\%[0-9]*[xsdfo]|\%n|\%p|\%x|\%d'

        # Create features DataFrame
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
                    df['body'].fillna('').astype(str).str.lower().str.contains(sql_pattern, regex=True) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(sql_pattern, regex=True)
            ).astype(int),
            'has_script_tags': (
                    df['body'].fillna('').astype(str).str.lower().str.contains(script_pattern, regex=True) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(script_pattern, regex=True) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(dangerous_url_pattern, regex=True) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(format_string_pattern, regex=True)
            ).astype(int)
        })

        # Log the detection results
        logger.info("\nFeature Extraction Results:")
        logger.info(f"SQL Keywords detected: {features['has_sql_keywords'].iloc[0]}")
        logger.info(f"Script/Dangerous Content detected: {features['has_script_tags'].iloc[0]}")
        logger.info(f"Query present: {features['has_query'].iloc[0]}")
        logger.info(f"Path depth: {features['path_depth'].iloc[0]}")
        logger.info(f"All features: {features.iloc[0].to_dict()}")

        return features

    def predict_anomaly(self, data):
        if self.ml_model is None or self.vectorizer is None:
            raise ValueError("ML model or vectorizer not loaded")

        try:
            logger.info("\nPrediction Process:")
            path = data.get('path', '')
            query = data.get('query', '')
            logger.info(f"Using path for vectorization: {path}")

            X = self.extract_features(data)

            # Define critical attack patterns
            critical_patterns = {
                'sql_injection': r'(\b|;)(select|drop|update|delete|insert|alter|union)\b',
                'path_traversal': r'\.\.\/|\/etc\/|\/var\/|\/root\/',
                'rfi': r'https?:\/\/|file:\/\/|ftp:\/\/',
                'command_injection': r';\s*\w+|\|\s*\w+|\`.*\`',
                'xss': r'<[^>]*>|javascript:|data:|alert\s*\(|eval\s*\('
            }

            # Check for critical patterns
            attack_matches = {}
            for attack_type, pattern in critical_patterns.items():
                match_in_query = bool(re.search(pattern, query.lower()))
                match_in_path = bool(re.search(pattern, path.lower()))
                match_in_body = bool(re.search(pattern, data.get('body', '').lower()))
                attack_matches[attack_type] = match_in_query or match_in_path or match_in_body

            logger.info("Attack Pattern Matches:")
            for attack_type, matched in attack_matches.items():
                logger.info(f"{attack_type}: {matched}")

            # If any critical pattern matches, it's definitely an attack
            if any(attack_matches.values()):
                logger.info("Critical attack pattern detected!")
                return True

            # If no critical patterns, proceed with ML prediction
            path_features = self.vectorizer.transform([path])
            logger.info(f"Path features generated with shape: {path_features.shape}")

            if self.preprocessor:
                X_preprocessed = self.preprocessor.transform(X)
                logger.info(f"Preprocessed features shape: {X_preprocessed.shape}")

                if issparse(X_preprocessed):
                    X_preprocessed = X_preprocessed.toarray()
                if issparse(path_features):
                    path_features = path_features.toarray()

                X_combined = np.hstack((X_preprocessed, path_features))
                logger.info(f"Combined feature shape: {X_combined.shape}")

                # Make prediction with probability
                prediction_proba = self.ml_model.predict_proba(X_combined)
                attack_probability = prediction_proba[0][1]

                logger.info(f"Attack probability from ML: {attack_probability}")

                # Use different thresholds based on feature presence
                has_query = X['has_query'].iloc[0] == 1
                has_suspicious_content = (X['has_sql_keywords'].iloc[0] == 1 or
                                          X['has_script_tags'].iloc[0] == 1)

                # Lower threshold if request has suspicious characteristics
                threshold = 0.3 if (has_query or has_suspicious_content) else 0.5

                logger.info(f"Using threshold: {threshold} (adjusted based on request characteristics)")
                final_prediction = attack_probability > threshold

                logger.info(f"Final prediction: {final_prediction}")
                return bool(final_prediction)
            else:
                raise ValueError("Preprocessor not loaded")

        except Exception as e:
            logger.error(f"Error in predict_anomaly: {str(e)}")
            raise

    def generate_rule_from_anomaly(self, data):
        # Enhanced rule generation
        suspicious_patterns = []

        # Check path for suspicious patterns
        if 'path' in data and data['path']:
            if any(keyword in data['path'].lower() for keyword in ['admin', 'shell', 'exec', 'eval']):
                suspicious_patterns.append(('path', data['path']))

        # Check body for suspicious patterns
        if data.get('body'):
            if any(keyword in str(data['body']).lower() for keyword in ['script', 'select', 'union', 'delete']):
                suspicious_patterns.append(('body', str(data['body'])))

        # Generate rules for suspicious patterns
        for field, value in suspicious_patterns:
            pattern = re.escape(value)
            name = f"ML_Generated_Rule_{field}_{len(self.rules)}"
            self.add_rule(name, pattern, field)
            return name

        return None