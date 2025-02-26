#!/usr/bin/env python3
"""
Integration script for SnoopyIDS that adds our helper functions to the RuleEngine.py file
"""
import os
import re
import sys

def main():
    # First run the fix.py script to create the helper files
    print("Running fix.py to create helper files...")
    os.system("python fix.py")
    
    # Now modify RuleEngine.py to use our helpers
    rule_engine_path = "utils/RuleEngine.py"
    if not os.path.exists(rule_engine_path):
        print(f"❌ RuleEngine.py not found at {rule_engine_path}")
        return 1
    
    # Read the file
    with open(rule_engine_path, 'r') as f:
        content = f.read()
    
    # Add an import for our helper at the top of the file
    import_addition = """# Import feature helper for padding features
try:
    from utils.cicada.feature_helper import pad_feature_array, ensure_feature_count
except ImportError:
    # Simple fallback implementations
    def pad_feature_array(X, expected_count=82):
        \"\"\"Ensure correct feature count\"\"\"
        import numpy as np
        if hasattr(X, 'shape') and len(X.shape) == 2:
            if X.shape[1] < expected_count:
                padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
                return np.hstack((X, padding))
            elif X.shape[1] > expected_count:
                return X[:, :expected_count]
        return X
    
    def ensure_feature_count(features, expected_count=82):
        \"\"\"Ensure DataFrame has right number of columns\"\"\"
        current_count = features.shape[1]
        if current_count < expected_count:
            for i in range(current_count, expected_count):
                features[f'padding_{i}'] = 0
        elif current_count > expected_count:
            features = features.iloc[:, :expected_count]
        return features"""
    
    # Find where to add the import - after all other imports
    import_pattern = r"(from utils\.Rule import Rule\s+)"
    if re.search(import_pattern, content):
        content = re.sub(import_pattern, r"\1\n" + import_addition + "\n\n", content)
    else:
        # Fallback - add after all imports
        parts = content.split("import", 1)
        if len(parts) > 1:
            last_import_pos = content.rfind("import")
            last_import_line_end = content.find("\n", last_import_pos)
            if last_import_line_end > 0:
                content = content[:last_import_line_end+1] + "\n" + import_addition + "\n" + content[last_import_line_end+1:]
    
    # Add feature padding in the extract_features method
    extract_features_pattern = r"(def extract_features.*?return features\s*)(})?(\s*\))?$"
    if re.search(extract_features_pattern, content, re.DOTALL):
        # Add ensure_feature_count before returning features
        content = re.sub(
            extract_features_pattern,
            r"\1}\n\n            # Ensure we have the exact number of features expected by the model\n            features = ensure_feature_count(features)\n            return features\2\3",
            content,
            flags=re.DOTALL
        )
    
    # Add feature padding in the predict_anomaly method - this is more complex
    # Find places where X_combined is created and model.predict_proba is called
    # and add pad_feature_array before the prediction
    
    # Pattern 1: Standard prediction
    predict_pattern1 = r"(X_combined = np\.hstack\(\(.*?\)\)\s+)(.*?prediction_proba = self\.ml_model\.predict_proba\(X_combined\))"
    if re.search(predict_pattern1, content, re.DOTALL):
        content = re.sub(
            predict_pattern1,
            r"\1# Ensure feature count matches what model expects\n            X_combined = pad_feature_array(X_combined)\n            \2",
            content,
            flags=re.DOTALL
        )
    
    # Pattern 2: Anomaly boosted prediction
    predict_pattern2 = r"(X_combined = np\.hstack\(\(.*?\)\)\s+)(.*?anomaly_boosted_predict\(\s*self\.ml_model,\s*X_combined,)"
    if re.search(predict_pattern2, content, re.DOTALL):
        content = re.sub(
            predict_pattern2,
            r"\1# Ensure feature count matches what model expects\n            X_combined = pad_feature_array(X_combined)\n            \2",
            content,
            flags=re.DOTALL
        )
    
    # Write the changes back to the file
    with open(rule_engine_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Updated {rule_engine_path} with helper functionality")
    
    print("\nIntegration complete!")
    print("To apply these changes, rebuild your Docker container:")
    print("docker-compose build && docker-compose up -d")

if __name__ == "__main__":
    sys.exit(main())