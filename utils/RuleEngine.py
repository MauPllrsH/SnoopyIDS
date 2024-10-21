import json
import re

import joblib
from bson import ObjectId
from pymongo import MongoClient

from utils.Rule import Rule


class RuleEngine:
    def __init__(self, mongo_uri, db_name, collection_name):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.rules = []
        self.ml_model = None
        self.vectorizer = None

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
        self.load_rules()  # Reload rules after updating

    def delete_rule(self, rule_id):
        self.collection.delete_one({'_id': ObjectId(rule_id)})
        self.load_rules()  # Reload rules after deleting

    def load_ml_model(self, model_path, vectorizer_path):
        self.ml_model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)

    def predict_anomaly(self, data):
        if self.ml_model is None or self.vectorizer is None:
            raise ValueError("ML utils or vectorizer not loaded")

        data_str = json.dumps(data)

        vector = self.vectorizer.transform([data_str])

        prediction = self.ml_model.predict(vector)

        return prediction[0] == 1

    def generate_rule_from_anomaly(self, data):
        # VERY SIMPLE IMPLEMENTATION, more work required.
        for key, value in data.items():
            if isinstance(value, str):
                pattern = re.escape(value)
                name = f"ML_Generated_Rule_{key}"
                self.add_rule(name, pattern, key)
                return name
        return None