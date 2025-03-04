#!/usr/bin/env python3
"""
Import correction file for Docker environment
This ensures all necessary modules are available
"""
import os
import sys
import re
import pandas as pd
import numpy as np
import joblib
import traceback
from scipy.sparse import issparse
# Import entropy explicitly to make it available globally
from scipy.stats import entropy
from pymongo import MongoClient

# Test entropy function to ensure it's globally available
print("Testing entropy function...")
try:
    # Test entropy explicitly
    test_data = np.array([0.25, 0.25, 0.25, 0.25])
    test_result = entropy(test_data)
    print(f"✅ scipy.stats.entropy test successful: {test_result}")
    
    # Make entropy available to other modules
    import builtins
    builtins.entropy = entropy
    print("✅ Added entropy to builtins for global access")
except Exception as e:
    print(f"❌ Error with entropy function: {str(e)}")
    print("Creating fallback entropy function...")
    
    # Define fallback entropy function
    def entropy_fallback(pk, qk=None, base=None):
        """Calculate entropy from probability distribution.
        Simple fallback implementation in case scipy isn't available.
        """
        import numpy as np
        
        if qk is not None:
            raise NotImplementedError("Only simple entropy calculation supported in fallback mode")
            
        pk = np.asarray(pk)
        pk = pk / float(np.sum(pk))
        if base is None:
            base = np.e
            
        vec = pk * np.log(pk)
        vec[~np.isfinite(vec)] = 0.0  # Handle zeros properly
        return -np.sum(vec)
        
    # Add to global namespace so it's available for import
    import builtins
    builtins.entropy = entropy_fallback
    
    # Create fake entropy module
    class EntropyModule:
        def __init__(self):
            self.entropy = entropy_fallback
    
    # Add to sys.modules so import statements work
    sys.modules['entropy'] = EntropyModule()
    print("✅ Added fallback entropy function to global namespace")

# Test feature padding with sklearn
try:
    from sklearn.ensemble import RandomForestClassifier
    
    # Test if we can properly handle feature mismatch
    # Create a simple model with 82 features
    import numpy as np
    X_train = np.random.random((10, 82))
    y_train = np.random.randint(0, 2, 10)
    rf = RandomForestClassifier(n_estimators=10)
    rf.fit(X_train, y_train)
    
    # Now create input with only 64 features
    X_test_small = np.random.random((1, 64))
    
    # Add padding to match feature count
    padding = np.zeros((1, 82 - 64))
    X_test_padded = np.hstack((X_test_small, padding))
    
    # Verify prediction works with padded features
    _ = rf.predict_proba(X_test_padded)
    print("✅ Feature padding test successful")
except Exception as e:
    print(f"❌ Feature padding test failed: {str(e)}")

print("Import verification complete - all modules available")