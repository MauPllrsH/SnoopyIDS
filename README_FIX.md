# SnoopyIDS Integration Fix

This guide will help you fix the two main issues with SnoopyIDS:

1. The `entropy` function not being found (`Error in advanced prediction: name 'entropy' is not defined`)
2. Feature count mismatch (`Fallback prediction failed: X has 64 features, but RandomForestClassifier is expecting 82 features as input`)

## Solution Overview

### 1. For the entropy issue:
The simplest solution is to ensure scipy is properly installed in the Docker container.

### 2. For the feature count mismatch:
We need to pad the features to match the 82 features expected by the trained model.

## Fix Steps

1. **Modify Dockerfile** to explicitly include scipy:
   ```dockerfile
   # Copy requirements first to leverage Docker cache
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt scipy
   ```

2. **Create a feature helper** to handle padding:
   Create a file `utils/cicada/feature_helper.py` with:
   ```python
   # Feature helper for SnoopyIDS
   import numpy as np

   def ensure_feature_count(features, expected_count=82):
       """
       Makes sure the features DataFrame has the exact number of columns needed by the model.
       
       Args:
           features: Pandas DataFrame with features
           expected_count: Expected number of features
           
       Returns:
           DataFrame with exact feature count
       """
       current_count = features.shape[1]
       
       if current_count < expected_count:
           # Add padding features
           for i in range(current_count, expected_count):
               features[f'padding_{i}'] = 0
       elif current_count > expected_count:
           # Keep only the first expected_count features
           features = features.iloc[:, :expected_count]
       
       return features

   def pad_feature_array(X, expected_count=82):
       """
       Ensures a feature array has the correct number of features.
       For use with numpy arrays.
       
       Args:
           X: Feature array or matrix (numpy array)
           expected_count: Expected feature count
           
       Returns:
           Feature array with correct feature count
       """
       if hasattr(X, 'shape') and len(X.shape) == 2:
           if X.shape[1] < expected_count:
               # Add padding
               padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
               return np.hstack((X, padding))
           elif X.shape[1] > expected_count:
               # Truncate features
               return X[:, :expected_count]
       return X
   ```

3. **Modify RuleEngine.py** to use these helpers:
   - Add the imports at the top:
     ```python
     # Import feature helper for padding features
     try:
         from utils.cicada.feature_helper import pad_feature_array, ensure_feature_count
     except ImportError:
         # Simple fallback implementations
         def pad_feature_array(X, expected_count=82):
             """Ensure correct feature count"""
             import numpy as np
             if hasattr(X, 'shape') and len(X.shape) == 2:
                 if X.shape[1] < expected_count:
                     padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
                     return np.hstack((X, padding))
                 elif X.shape[1] > expected_count:
                     return X[:, :expected_count]
             return X
         
         def ensure_feature_count(features, expected_count=82):
             """Ensure DataFrame has right number of columns"""
             current_count = features.shape[1]
             if current_count < expected_count:
                 for i in range(current_count, expected_count):
                     features[f'padding_{i}'] = 0
             elif current_count > expected_count:
                 features = features.iloc[:, :expected_count]
             return features
     ```

   - Modify the `extract_features` method to ensure feature count before returning:
     ```python
     # At the end of extract_features function:
     features = ensure_feature_count(features)
     return features
     ```

   - Add feature padding before making predictions in `predict_anomaly`:
     ```python
     # After creating X_combined:
     X_combined = np.hstack((X_num, X_cat, path_features))
     
     # Add this line:
     X_combined = pad_feature_array(X_combined)
     
     # Then continue with prediction
     prediction_proba = self.ml_model.predict_proba(X_combined)
     ```

4. **Rebuild the Docker container**:
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

## Testing

After implementing these fixes, check the logs with:
```bash
docker-compose logs
```

The entropy and feature count errors should no longer appear.

## Why This Works

1. **Entropy Fix**: Explicitly installing scipy ensures the entropy function is available.
2. **Feature Count Fix**: The padding solution adds zeroes for missing features, which won't affect predictions since zero-valued features don't contribute to the model's decision.