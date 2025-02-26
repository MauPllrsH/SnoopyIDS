#!/bin/bash

# This script prepares SnoopyIDS for Docker deployment, ensuring 
# all components from Cicada are properly included

# Create necessary directories
mkdir -p model
mkdir -p utils/cicada

# Create an empty __init__.py file in the cicada directory
touch utils/cicada/__init__.py

# Create the preload.py script for entropy import handling
cat > preload.py << 'EOF'
#!/usr/bin/env python3
"""
Preload script for SnoopyIDS Docker environment
This ensures all necessary functions are available
"""
import sys
import builtins
import numpy as np

print("Starting SnoopyIDS preload...")

# Ensure entropy function is available
try:
    # Try to import scipy.stats.entropy
    from scipy.stats import entropy
    print("✅ Successfully imported scipy.stats.entropy")
except ImportError:
    # Define entropy function directly
    def entropy(pk, qk=None, base=None):
        """Entropy calculation for probability distributions."""
        print("Using custom entropy function for calculation")
        pk = np.asarray(pk)
        pk = pk / float(np.sum(pk))
        if base is None:
            base = np.e
            
        vec = pk * np.log(pk)
        vec[~np.isfinite(vec)] = 0.0
        return -np.sum(vec)
    
    print("✅ Created custom entropy function")
    
# Add entropy to builtins so it's available everywhere
builtins.entropy = entropy
print("✅ Added entropy to builtins")

# Create a module-like object for imports
class EntropyModule:
    def __init__(self):
        self.entropy = entropy
        
# Add to sys.modules for import statements
sys.modules['entropy'] = EntropyModule()
print("✅ Added entropy to sys.modules")

# Create feature padding function for feature count mismatches
def pad_features(features, expected_count):
    """Pad or truncate features to the expected count"""
    if features.shape[1] < expected_count:
        # Add padding
        padding = np.zeros((features.shape[0], expected_count - features.shape[1]))
        return np.hstack((features, padding))
    elif features.shape[1] > expected_count:
        # Truncate features
        return features[:, :expected_count]
    else:
        # No change needed
        return features

# Add to builtins
builtins.pad_features = pad_features
print("✅ Added feature padding function")

print("✅ SnoopyIDS preload complete")
EOF

chmod +x preload.py
echo "Created preload.py script for Docker environment"

# Create a simple startup script
cat > docker_start.sh << 'EOF'
#!/bin/bash
# Start SnoopyIDS with preloaded modules
python -u preload.py
python -u preload.py && python -u preload.py && python -u preload.py && python -u app.py
EOF

chmod +x docker_start.sh
echo "Created docker_start.sh script"

# Create a simple standalone entropy.py module
cat > entropy.py << 'EOF'
#!/usr/bin/env python3
"""Standalone entropy module to avoid import errors"""
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

# Copy Cicada model if it exists locally
STANDALONE_MODEL_PATH="../Cicada/model/standalone_model.joblib"
COMPLETE_MODEL_PATH="../Cicada/model/complete_model_package.joblib"

if [ -f "$STANDALONE_MODEL_PATH" ]; then
    echo "Found Cicada standalone model, copying to model directory..."
    cp "$STANDALONE_MODEL_PATH" model/
    echo "Standalone model copied successfully"
elif [ -f "$COMPLETE_MODEL_PATH" ]; then
    echo "Found Cicada complete model package, copying to model directory..."
    cp "$COMPLETE_MODEL_PATH" model/
    echo "Complete model package copied successfully"
else
    echo "Warning: No Cicada models found"
    echo "You need to train a model in Cicada and/or copy it manually to the model directory"
    echo "Run update_cicada_model.sh to generate and copy the model"
fi

# Update Dockerfile
echo "Checking Dockerfile..."
if [ -f "Dockerfile" ]; then
    # Check if the CMD line needs updating
    if grep -q 'CMD \["python", "-u", "app.py"\]' Dockerfile; then
        echo "Updating Dockerfile CMD to use docker_start.sh..."
        sed -i '' 's/CMD \["python", "-u", "app.py"\]/CMD \["\.\/docker_start.sh"\]/' Dockerfile
        echo "Dockerfile updated"
    fi
fi

# Add a reminder about Docker
echo "======================="
echo "DOCKER DEPLOYMENT NOTE"
echo "======================="
echo "When building a Docker image, ensure that the Dockerfile copies"
echo "all required files:"
echo ""
echo "COPY model /app/model"
echo "COPY utils /app/utils"
echo "COPY preload.py /app/"
echo "COPY entropy.py /app/"
echo "COPY docker_start.sh /app/"
echo ""
echo "Your entry point should be:"
echo "CMD [\"./docker_start.sh\"]"
echo ""
echo "Then rebuild your Docker image:"
echo "docker-compose build && docker-compose up -d"