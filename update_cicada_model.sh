#!/bin/bash

# This script updates SnoopyIDS with the latest model from Cicada
# It works with both local and Docker environments and ensures
# all required code and modules are properly copied

# Set paths
CICADA_DIR="../Cicada"
SNOOPY_DIR="."
CICADA_MODEL_PATH="$CICADA_DIR/model/standalone_model.joblib"
SNOOPY_MODEL_PATH="$SNOOPY_DIR/model/standalone_model.joblib"

echo "=== SnoopyIDS Cicada Model Updater ==="
echo "Updating SnoopyIDS with the latest model and supporting code from Cicada"

# Check if Cicada directory exists
if [ ! -d "$CICADA_DIR" ]; then
    echo "Error: Cicada directory not found at $CICADA_DIR"
    echo "Please update the CICADA_DIR variable in this script"
    exit 1
fi

# Check if standalone model exists
if [ ! -f "$CICADA_MODEL_PATH" ]; then
    echo "Standalone model not found at $CICADA_MODEL_PATH"
    echo "Attempting to generate standalone model..."
    
    # Try to run the export script
    if [ -f "$CICADA_DIR/export_standalone_model.py" ]; then
        echo "Running export_standalone_model.py..."
        (cd "$CICADA_DIR" && python export_standalone_model.py)
        
        # Check if export was successful
        if [ ! -f "$CICADA_MODEL_PATH" ]; then
            echo "Error: Failed to generate standalone model"
            echo "Please run Cicada's export_standalone_model.py manually"
            exit 1
        fi
    else
        echo "Error: export_standalone_model.py not found in Cicada directory"
        echo "Please run Cicada option 1 to train a model first"
        exit 1
    fi
fi

# Create SnoopyIDS model directory if it doesn't exist
mkdir -p "$SNOOPY_DIR/model"

# Copy the model
echo "Copying model from Cicada to SnoopyIDS..."
cp "$CICADA_MODEL_PATH" "$SNOOPY_MODEL_PATH"

if [ $? -eq 0 ]; then
    echo "Model copied successfully!"
else
    echo "Error: Failed to copy model file"
    exit 1
fi

# Create necessary directories for Cicada code
echo "Setting up Cicada code structure in SnoopyIDS..."
mkdir -p "$SNOOPY_DIR/utils/cicada"

# Create an empty __init__.py file for the cicada package
touch "$SNOOPY_DIR/utils/cicada/__init__.py"

# Create an anomaly_boosting.py file if it doesn't exist
if [ ! -f "$SNOOPY_DIR/utils/cicada/anomaly_boosting.py" ]; then
    echo "Creating anomaly_boosting.py..."
    cat > "$SNOOPY_DIR/utils/cicada/anomaly_boosting.py" << 'EOF'
import numpy as np

def anomaly_boosted_predict(model, X, iso_model, threshold=0.5, iso_weight=0.3):
    """
    Boost model predictions with anomaly detection scores
    - model: main classifier (voting ensemble)
    - X: feature matrix
    - iso_model: isolation forest model
    - threshold: base decision threshold
    - iso_weight: weight to give to anomaly scores (0-1)
    """
    # Get base model prediction probabilities
    base_probs = model.predict_proba(X)[:, 1]
    
    # Get anomaly scores (-1 to 1, where lower is more anomalous)
    raw_scores = iso_model.decision_function(X)
    
    # Normalize scores to 0-1 range and invert (1 = more anomalous)
    min_score, max_score = min(raw_scores), max(raw_scores)
    norm_scores = 1 - ((raw_scores - min_score) / (max_score - min_score + 1e-10))
    
    # Combine scores (weighted average)
    combined_probs = (1 - iso_weight) * base_probs + iso_weight * norm_scores
    
    # Make final predictions
    predictions = (combined_probs >= threshold).astype(int)
    return predictions, combined_probs
EOF
fi

# Copy Cicada feature extraction and alignment code
echo "Updating feature extractor from Cicada..."
cp "$CICADA_DIR/src/features/feature_extractor.py" "$SNOOPY_DIR/utils/cicada/feature_extractor.py"

echo "Updating feature alignment from Cicada..."
cp "$CICADA_DIR/utils/feature_alignment.py" "$SNOOPY_DIR/utils/cicada/feature_alignment.py"

# Fix import in feature_alignment.py for SnoopyIDS compatibility
sed -i '' 's/from src.features.feature_extractor import extract_features/from utils.cicada.feature_extractor import extract_features/' "$SNOOPY_DIR/utils/cicada/feature_alignment.py"

# Add entropy import handling to feature_extractor.py
echo "Adding entropy function handling to feature_extractor.py..."
sed -i '' '1s/^/import builtins\nimport sys\n\n# Handle entropy import\ntry:\n    from scipy.stats import entropy\nexcept ImportError:\n    # Define fallback entropy function\n    def entropy(pk, qk=None, base=None):\n        """Fallback entropy function."""\n        import numpy as np\n        \n        pk = np.asarray(pk)\n        pk = pk / float(np.sum(pk))\n        if base is None:\n            base = np.e\n            \n        vec = pk * np.log(pk)\n        vec[~np.isfinite(vec)] = 0.0\n        return -np.sum(vec)\n    \n    # Add to global namespace\n    builtins.entropy = entropy\n\n/' "$SNOOPY_DIR/utils/cicada/feature_extractor.py"

# Create an entropy.py in root directory so it can be imported directly
echo "Creating standalone entropy.py..."
cat > "$SNOOPY_DIR/entropy.py" << 'EOF'
#!/usr/bin/env python3
"""
Standalone entropy module to avoid import errors
This file provides the entropy function directly
"""
import numpy as np

def entropy(pk, qk=None, base=None):
    """Calculate entropy from probability distribution."""
    pk = np.asarray(pk)
    pk = pk / float(np.sum(pk))
    if base is None:
        base = np.e
        
    vec = pk * np.log(pk)
    vec[~np.isfinite(vec)] = 0.0  # Handle zeros properly
    return -np.sum(vec)
EOF

# Create a preload.py file for Docker
echo "Creating preload.py for Docker environment..."
cat > "$SNOOPY_DIR/preload.py" << 'EOF'
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
EOF

# Update docker_setup.sh to run preload.py
if [ -f "$SNOOPY_DIR/docker_setup.sh" ]; then
    echo "Updating docker_setup.sh..."
    sed -i '' 's/python -u app.py/python -u preload.py \&\& python -u app.py/' "$SNOOPY_DIR/docker_setup.sh"
fi

# Check if we're in a Docker environment
if [ -f "$SNOOPY_DIR/Dockerfile" ] || [ -f "$SNOOPY_DIR/docker-compose.yml" ]; then
    echo "Docker environment detected"
    echo "IMPORTANT: You need to rebuild your Docker image for changes to take effect"
    echo "Run: docker-compose build && docker-compose up -d"
fi

echo ""
echo "Update complete! SnoopyIDS will use the new Cicada model on next restart."
echo "All supporting code has been properly updated to ensure compatibility."
echo "This update includes:"
echo "- The latest standalone model"
echo "- Cicada's feature extraction code"
echo "- Entropy function handling"
echo "- Feature alignment utilities"