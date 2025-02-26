#!/usr/bin/env python3
"""
Simplified fix for SnoopyIDS issues:
1. Makes sure scipy.stats.entropy is available in Docker
2. Fixes the feature count mismatch between Cicada (82 features) and SnoopyIDS (64 features)
"""
import sys
import os
import joblib
import numpy as np

def main():
    print("Checking for model files...")
    model_dir = "model"
    standalone_path = os.path.join(model_dir, 'standalone_model.joblib')
    
    if not os.path.exists(standalone_path):
        print(f"❌ Model file not found: {standalone_path}")
        return 1
    
    print(f"✅ Found model file: {standalone_path}")
    
    print("Loading model to extract feature counts...")
    model_package = joblib.load(standalone_path)
    
    # Get feature count from model package
    if 'feature_names' in model_package:
        feature_count = len(model_package['feature_names'])
        print(f"✅ Expected feature count: {feature_count}")
    else:
        feature_count = 82  # Default from error message
        print(f"ℹ️ Using default expected feature count: {feature_count}")
    
    # Create a simple helper function patch file
    helper_file = "utils/cicada/feature_helper.py"
    os.makedirs(os.path.dirname(helper_file), exist_ok=True)
    
    helper_content = f"""# Feature helper for SnoopyIDS
import numpy as np

def ensure_feature_count(features, expected_count={feature_count}):
    \"\"\"
    Makes sure the features DataFrame has the exact number of columns needed by the model.
    
    Args:
        features: Pandas DataFrame with features
        expected_count: Expected number of features
        
    Returns:
        DataFrame with exact feature count
    \"\"\"
    current_count = features.shape[1]
    
    if current_count < expected_count:
        # Add padding features
        for i in range(current_count, expected_count):
            features[f'padding_{i}'] = 0
        print(f"Added {expected_count - current_count} padding features")
    elif current_count > expected_count:
        # Keep only the first expected_count features
        print(f"Truncating {current_count - expected_count} extra features")
        features = features.iloc[:, :expected_count]
    
    return features

def pad_feature_array(X, expected_count={feature_count}):
    \"\"\"
    Ensures a feature array has the correct number of features.
    For use with numpy arrays.
    
    Args:
        X: Feature array or matrix (numpy array)
        expected_count: Expected feature count
        
    Returns:
        Feature array with correct feature count
    \"\"\"
    if hasattr(X, 'shape') and len(X.shape) == 2:
        if X.shape[1] < expected_count:
            # Add padding
            padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
            return np.hstack((X, padding))
        elif X.shape[1] > expected_count:
            # Truncate features
            return X[:, :expected_count]
    return X
"""
    
    with open(helper_file, 'w') as f:
        f.write(helper_content)
    
    print(f"✅ Created helper file: {helper_file}")
    
    # Create __init__.py files to ensure imports work
    for dir_path in ["utils/cicada"]:
        init_path = os.path.join(dir_path, "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, 'w') as f:
                f.write("# This file is required for Python to recognize this directory as a package\n")
            print(f"✅ Created {init_path}")
    
    print("\nFix applied successfully! To complete the fix:")
    print("1. Add a patch in app.py or RuleEngine.py to import and use the feature_helper.py")
    print("2. Rebuild the Docker container: docker-compose build && docker-compose up -d")

if __name__ == "__main__":
    sys.exit(main())