#!/usr/bin/env python3
"""
Standalone model testing and importing script.
This directly tests model loading and prediction, bypassing the regular code to isolate issues.
"""
import os
import sys
import numpy as np
import pandas as pd
import joblib
import traceback

# Define our own entropy function to avoid any import issues
def calc_entropy(pk, qk=None, base=None):
    """Calculate entropy from probability distribution."""
    if not isinstance(pk, (list, np.ndarray)):
        return 0
        
    pk = np.asarray(pk)
    if np.sum(pk) == 0:
        return 0
        
    pk = pk / float(np.sum(pk))
    if base is None:
        base = np.e
        
    vec = pk * np.log(pk)
    vec[~np.isfinite(vec)] = 0.0  # Handle zeros properly
    return -np.sum(vec)

# Override the sys.modules to provide entropy function
class EntropyModule:
    def __init__(self):
        self.entropy = calc_entropy
        
# Add our fake entropy module to sys.modules
sys.modules['entropy'] = EntropyModule()

# Also directly add to builtins
import builtins
builtins.entropy = calc_entropy

# Directly add to globals
globals()['entropy'] = calc_entropy

print("Starting model test...")

try:
    # Load the model
    model_path = os.path.join('model', 'standalone_model.joblib')
    print(f"Loading model from {model_path}...")
    model_package = joblib.load(model_path)
    print("Model loaded successfully!")
    
    # Check what's in the model
    print(f"Model package keys: {list(model_package.keys())}")
    
    # Try to extract the prediction function
    if 'code' in model_package and 'predict_function' in model_package:
        code = model_package['code']
        predict_function_name = model_package['predict_function']
        
        print(f"Found prediction function '{predict_function_name}'")
        
        # Create a namespace
        namespace = {}
        
        # Add our libraries to the namespace
        namespace['pd'] = pd 
        namespace['np'] = np
        namespace['entropy'] = calc_entropy
        namespace['issparse'] = lambda x: False  # Simple stub
        namespace['os'] = os
        namespace['sys'] = sys
        
        # Execute the code
        print("Executing prediction code...")
        exec(code, namespace)
        
        # Get the prediction function
        predict_function = namespace.get(predict_function_name)
        if predict_function:
            print("Successfully loaded prediction function!")
            
            # Create test data
            test_data = pd.DataFrame([{
                'timestamp': '2025-02-26T05:23:49',
                'type': 'http',
                'ip': '192.168.1.1',
                'method': 'GET',
                'path': '/test',
                'query': '',
                'headers': {'user-agent': 'test-agent'},
                'body': '',
                'client_id': 'test-client'
            }])
            
            # Create model components
            model_components = {
                'model': model_package.get('model'),
                'iso_model': model_package.get('iso_model'),
                'vectorizer': model_package.get('vectorizer'),
                'preprocessor': model_package.get('preprocessor'),
                'feature_names': model_package.get('feature_names', []),
                'threshold': model_package.get('threshold', 0.5),
                'iso_weight': model_package.get('iso_weight', 0.3)
            }
            
            # Try prediction
            print("Attempting prediction...")
            try:
                is_attack, confidence = predict_function(test_data, model_components)
                print(f"Prediction successful! is_attack={is_attack}, confidence={confidence:.4f}")
            except Exception as e:
                print(f"Prediction failed: {str(e)}")
                print(traceback.format_exc())
                
                # Try with emergency feature creation
                print("\nTrying emergency feature creation...")
                expected_feature_count = 82
                features = np.zeros((1, expected_feature_count))
                
                # Make prediction directly
                try:
                    model = model_components['model']
                    print(f"Model type: {type(model).__name__}")
                    
                    # Try to find the actual predict_proba method
                    def find_model_with_predict(model_obj, depth=0):
                        if depth > 3:
                            return None
                        if hasattr(model_obj, 'predict_proba'):
                            return model_obj
                        if isinstance(model_obj, dict):
                            for k, v in model_obj.items():
                                result = find_model_with_predict(v, depth+1)
                                if result:
                                    return result
                        return None
                    
                    actual_model = find_model_with_predict(model)
                    if actual_model:
                        print(f"Found model with predict_proba: {type(actual_model).__name__}")
                        probs = actual_model.predict_proba(features)
                        print(f"Direct prediction successful! probs={probs}")
                    else:
                        print("Could not find a model with predict_proba")
                except Exception as e2:
                    print(f"Emergency prediction failed: {str(e2)}")
                    print(traceback.format_exc())
        else:
            print(f"Prediction function '{predict_function_name}' not found in the code!")
    else:
        print("No prediction code found in the model package!")

except Exception as e:
    print(f"Error during model test: {str(e)}")
    print(traceback.format_exc())

print("\nTest completed.")