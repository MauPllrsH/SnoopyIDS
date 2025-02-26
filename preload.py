import sys
import builtins
import importlib.util
import numpy as np

print("Starting preload...")

# Ensure entropy function is available
try:
    # Try to import scipy.stats.entropy
    from scipy.stats import entropy
    print("Successfully imported scipy.stats.entropy")
except ImportError:
    # Define entropy function directly
    def entropy(pk, qk=None, base=None):
        """Entropy calculation for probability distributions."""
        pk = np.asarray(pk)
        pk = pk / float(np.sum(pk))
        if base is None:
            base = np.e
            
        vec = pk * np.log(pk)
        vec[~np.isfinite(vec)] = 0.0
        return -np.sum(vec)
    
    print("Using custom entropy function")
    
# Add entropy to builtins so it's available everywhere
builtins.entropy = entropy
print("Added entropy to builtins")

# Create a module-like object for imports
class EntropyModule:
    def __init__(self):
        self.entropy = entropy
        
# Add to sys.modules for import statements
sys.modules['entropy'] = EntropyModule()
print("Added entropy to sys.modules")

print("Preload complete")
