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
        self.ml_model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        if preprocessor_path:
            self.preprocessor = joblib.load(preprocessor_path)
        if label_encoder_path:
            self.label_encoder = joblib.load(label_encoder_path)

    def extract_features(self, data):
        # Convert single request to DataFrame
        df = pd.DataFrame([data])

        return pd.DataFrame({
            'method': df['method'],
            'has_body': df['body'].notna().astype(int),
            'header_count': df['headers'].apply(lambda x: len(x) if isinstance(x, dict) else 0),
            'has_query': df['path'].apply(lambda x: '?' in str(x)).astype(int),
            'content_type': df['headers'].apply(lambda x: 1 if 'content-type' in str(x).lower() else 0),
            'user_agent': df['headers'].apply(lambda x: 1 if 'user-agent' in str(x).lower() else 0),
            'body_length': df['body'].fillna('').astype(str).str.len(),
            'path_depth': df['path'].str.count('/'),
            'has_sql_keywords': df['body'].fillna('').astype(str).str.lower().str.contains(
                'select|from|where|union|insert|update|delete').astype(int),
            'has_script_tags': df['body'].fillna('').astype(str).str.lower().str.contains('<script').astype(int)
        })

    def predict_anomaly(self, data):
        if self.ml_model is None or self.vectorizer is None:
            raise ValueError("ML model or vectorizer not loaded")

        # Extract structured features
        X = self.extract_features(data)

        # Transform path using TF-IDF
        path_features = self.vectorizer.transform([data['path']])

        # Split features into categorical and numerical
        categorical_columns = ['method']
        numerical_columns = [col for col in X.columns if col not in categorical_columns]

        if self.preprocessor:
            # Apply preprocessing if available
            X_num = self.preprocessor.named_transformers_['num'].transform(X[numerical_columns])
            X_cat = self.preprocessor.named_transformers_['cat'].transform(X[categorical_columns])

            # Convert sparse matrices to dense if needed
            if issparse(X_num):
                X_num = X_num.toarray()
            if issparse(X_cat):
                X_cat = X_cat.toarray()
            if issparse(path_features):
                path_features = path_features.toarray()

            # Combine all features
            X_combined = np.hstack((X_num, X_cat, path_features))
        else:
            # Fallback to simpler processing if preprocessor not available
            if issparse(path_features):
                path_features = path_features.toarray()
            X_combined = path_features

        # Make prediction
        prediction = self.ml_model.predict(X_combined)
        return bool(prediction[0])

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