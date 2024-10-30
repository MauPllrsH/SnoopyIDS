import re
import pandas as pd
import numpy as np
from scipy.sparse import issparse
import joblib
from pymongo import MongoClient
from bson.objectid import ObjectId
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

        # Handle path and query splitting
        if 'path' in df.columns:
            split_result = df['path'].str.split('?', n=1, expand=True)
            df['path'] = split_result[0]
            df['query'] = split_result[1] if split_result.shape[1] > 1 else ''

        print("DEBUG - Original Path:", data['path'])
        print("DEBUG - Split Path:", df['path'].iloc[0])
        print("DEBUG - Query:", df['query'].iloc[0])

        # Enhanced attack detection patterns
        sql_pattern = r'select|from|where|union|insert|update|delete|drop|exec|system'
        script_pattern = r'<script|javascript:|data:|alert\(|eval\(|setTimeout|setInterval'
        dangerous_url_pattern = r'evil\.com|file://|http://|https://|ftp://|\/etc\/|\/var\/|\/root\/|\.\.\/|\%[0-9a-fA-F]{2}'
        format_string_pattern = r'\%[0-9]*[xsdfo]|\%n|\%p|\%x|\%d'

        # Create features DataFrame with enhanced detection
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
                    df['body'].fillna('').astype(str).str.lower().str.contains(sql_pattern) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(sql_pattern)
            ).astype(int),
            'has_script_tags': (
                    df['body'].fillna('').astype(str).str.lower().str.contains(script_pattern) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(script_pattern) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(dangerous_url_pattern) |
                    df['query'].fillna('').astype(str).str.lower().str.contains(format_string_pattern)
            ).astype(int)
        })

        # Print debug info
        print("\nDEBUG - Attack Indicators:")
        print(f"SQL Keywords: {features['has_sql_keywords'].iloc[0]}")
        print(f"Script/Dangerous Content: {features['has_script_tags'].iloc[0]}")
        print(f"Query Present: {features['has_query'].iloc[0]}")
        print(f"Path Depth: {features['path_depth'].iloc[0]}")
        print(f"All Features: {features.iloc[0].to_dict()}")

        return features

    def predict_anomaly(self, data):
        if self.ml_model is None or self.vectorizer is None:
            raise ValueError("ML model or vectorizer not loaded")

        try:
            # Extract structured features
            X = self.extract_features(data)
            print("Feature columns:", X.columns.tolist())

            # Get path features
            path = data['path'].split('?')[0] if '?' in data['path'] else data['path']
            path_features = self.vectorizer.transform([path])
            print("Path features shape:", path_features.shape)

            if self.preprocessor:
                # Get preprocessed features in same order as training
                X_preprocessed = self.preprocessor.transform(X)
                print("Preprocessed shape:", X_preprocessed.shape)

                # Convert to dense if needed
                if issparse(X_preprocessed):
                    X_preprocessed = X_preprocessed.toarray()
                if issparse(path_features):
                    path_features = path_features.toarray()

                # Combine features
                X_combined = np.hstack((X_preprocessed, path_features))
                print("Combined shape:", X_combined.shape)

                # Make prediction with probability
                prediction_proba = self.ml_model.predict_proba(X_combined)
                prediction = prediction_proba[0][1] > 0.5  # Use probability threshold

                print("Attack probability:", prediction_proba[0][1])
                print("Prediction:", prediction)

                return bool(prediction)
            else:
                raise ValueError("Preprocessor not loaded")

        except Exception as e:
            print(f"Error in predict_anomaly: {str(e)}")
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