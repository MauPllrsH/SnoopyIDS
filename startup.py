#!/usr/bin/env python3
"""
SnoopyIDS startup module to ensure all dependencies are ready 
before the main application is launched.
"""
import os
import sys
import builtins
import importlib.util
import numpy as np

print("Starting SnoopyIDS startup module...")

# Make sure entropy is available globally
print("Setting up entropy function...")
try:
    # First try to load our custom module
    spec = importlib.util.spec_from_file_location("entropy", os.path.join(os.getcwd(), "entropy.py"))
    entropy_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entropy_module)
    
    # Extract the entropy function
    entropy_func = getattr(entropy_module, "entropy")
    
    # Add to builtins
    builtins.entropy = entropy_func
    
    # Also add to sys.modules
    sys.modules['entropy'] = entropy_module
    
    print("✅ Custom entropy module loaded successfully")
except Exception as e:
    print(f"❌ Error loading custom entropy module: {str(e)}")
    print("Falling back to inline entropy definition")
    
    # Define entropy inline
    def entropy(pk, qk=None, base=None):
        if not isinstance(pk, (list, np.ndarray)):
            return 0
            
        pk = np.asarray(pk)
        if np.sum(pk) == 0:
            return 0
            
        pk = pk / float(np.sum(pk))
        if base is None:
            base = np.e
            
        vec = pk * np.log(pk)
        vec[~np.isfinite(vec)] = 0.0
        return -np.sum(vec)
    
    # Add to builtins and create a fake module
    builtins.entropy = entropy
    
    # Create a simple module
    class EntropyModule:
        def __init__(self):
            self.entropy = entropy
    
    # Add to sys.modules
    sys.modules['entropy'] = EntropyModule()
    print("✅ Fallback entropy definition added")

# Fix for scipy.stats.entropy issues
print("Patching scipy.stats.entropy...")
try:
    # Check if scipy.stats is available
    from scipy import stats
    
    # Make sure the entropy function is actually working
    try:
        test_array = np.array([0.25, 0.25, 0.25, 0.25])
        result = stats.entropy(test_array)
        print(f"✅ scipy.stats.entropy test successful: {result}")
    except Exception as test_error:
        print(f"❌ scipy.stats.entropy test failed: {str(test_error)}")
        # Override with our implementation
        stats.entropy = builtins.entropy
        print("✅ Patched scipy.stats.entropy with our implementation")
except ImportError:
    print("❌ scipy.stats not available")

# Create feature matching logic
print("Setting up feature matching...")
try:
    # Load pre-defined standard_features function from our entropy module
    standard_features = getattr(entropy_module, "standard_features")
    
    # Test the function
    test_data = {
        'method': 'GET',
        'path': '/test',
        'query': '',
        'body': '',
        'headers': {'user-agent': 'test'}
    }
    features = standard_features([test_data])
    print(f"✅ standard_features test successful: shape={features.shape}")
    
    # Add to globals
    builtins.standard_features = standard_features
except Exception as feat_error:
    print(f"❌ Feature matching setup failed: {str(feat_error)}")

print("SnoopyIDS startup module completed")