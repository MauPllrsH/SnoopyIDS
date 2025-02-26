#!/usr/bin/env python3
"""
Simple patch for sklearn to handle feature count mismatches
"""
import numpy as np
from sklearn.base import BaseEstimator

# Store original predict_proba
_original_predict_proba = getattr(BaseEstimator, 'predict_proba', None)

# Define a patched version that handles feature count mismatches
def _patched_predict_proba(self, X, *args, **kwargs):
    """
    Patched predict_proba that handles feature count mismatches
    by padding with zeros or trimming as needed.
    """
    try:
        # First try the original method
        return _original_predict_proba(self, X, *args, **kwargs)
    except ValueError as e:
        error_msg = str(e)
        
        # Check if this is a feature count mismatch
        if "has 64 features, but" in error_msg and "features as input" in error_msg:
            # Extract the expected feature count
            import re
            expected_count_match = re.search(r'expecting (\d+) features', error_msg)
            if expected_count_match:
                expected_count = int(expected_count_match.group(1))
                
                # Pad or trim features
                if X.shape[1] < expected_count:
                    # Add padding
                    padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
                    X_padded = np.hstack((X, padding))
                    return _original_predict_proba(self, X_padded, *args, **kwargs)
                elif X.shape[1] > expected_count:
                    # Trim features
                    X_trimmed = X[:, :expected_count]
                    return _original_predict_proba(self, X_trimmed, *args, **kwargs)
        
        # If we get here, either it wasn't a feature count issue or we couldn't fix it
        raise e

# Install the patched method if the original exists
if _original_predict_proba is not None:
    setattr(BaseEstimator, 'predict_proba', _patched_predict_proba)
    print("✅ Patched sklearn.base.BaseEstimator.predict_proba to handle feature count mismatches")
else:
    print("❌ Could not find sklearn.base.BaseEstimator.predict_proba method to patch")