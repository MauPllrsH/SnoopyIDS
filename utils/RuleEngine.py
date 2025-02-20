import re
import pandas as pd
import numpy as np
from scipy.sparse import issparse
import joblib
from pymongo import MongoClient
from bson.objectid import ObjectId
from utils.logger_config import logger

from utils.Rule import Rule


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

    def load_ml_model(self, model_path, vectorizer_path, preprocessor_path=None):
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

        return features

    def predict_anomaly(self, data):
        """Predict if request is anomalous with minimal logging."""
        if self.ml_model is None or self.vectorizer is None:
            raise ValueError("ML model or vectorizer not loaded")

        try:
            X = self.extract_features(data)
            path_features = self.vectorizer.transform([data.get('path', '')])

            if self.preprocessor:
                X_preprocessed = self.preprocessor.transform(X)

                if issparse(X_preprocessed):
                    X_preprocessed = X_preprocessed.toarray()
                if issparse(path_features):
                    path_features = path_features.toarray()

                X_combined = np.hstack((X_preprocessed, path_features))
                prediction_proba = self.ml_model.predict_proba(X_combined)
                attack_probability = prediction_proba[0][1]

                # Determine threshold
                has_query = X['has_query'].iloc[0] == 1
                has_suspicious_content = (X['has_sql_keywords'].iloc[0] == 1 or
                                          X['has_script_tags'].iloc[0] == 1)
                threshold = 0.3 if (has_query or has_suspicious_content) else 0.5

                return attack_probability > threshold, attack_probability

            else:
                raise ValueError("Preprocessor not loaded")

        except Exception as e:
            raise

    def generate_rule_from_anomaly(self, data):
        """Generate rules based purely on ML model's detection."""
        try:
            # Get ML features and vectorizer information
            features = self.extract_features(data)
            path = data.get('path', '')
            query = data.get('query', '')

            logger.info(f"Generating rules for detected attack - Path: {path}, Query: {query}")
            rules_to_generate = []

            # If query parameters exist and contributed to detection, create a query rule
            if query and features['has_query'].iloc[0] == 1:
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
                    path_pattern = f"^{re.escape(path)}$"  # Exact path match
                    rules_to_generate.append(('path', path_pattern))
                    logger.info(f"Generated path pattern: {path_pattern}")

            # Create and store rules
            created_rules = []
            for field, pattern in rules_to_generate:
                name = f"ML_Generated_Rule_{field}_{len(self.rules)}"
                logger.info(f"Creating new rule - Name: {name}, Field: {field}, Pattern: {pattern}")
                rule_id = self.add_rule(
                    name=name,
                    pattern=pattern,
                    field=field
                )
                created_rules.append(name)

            return created_rules[0] if created_rules else None

        except Exception as e:
            logger.error(f"Error generating rules from anomaly: {str(e)}")
            return None

    def extract_pattern_from_content(self, *contents, base_pattern):
        """Extract patterns from content that matched ML features."""
        for content in contents:
            if not content:
                continue
            content = str(content).lower()
            match = re.search(base_pattern, content)
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
