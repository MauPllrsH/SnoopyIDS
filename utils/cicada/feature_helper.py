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
        print(f"Added {expected_count - current_count} padding features")
    elif current_count > expected_count:
        # Keep only the first expected_count features
        print(f"Truncating {current_count - expected_count} extra features")
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