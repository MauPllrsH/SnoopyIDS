#!/bin/bash

# This script prepares SnoopyIDS for Docker deployment, ensuring 
# all components from Cicada are properly included

# Create necessary directories
mkdir -p model
mkdir -p utils/cicada

# Copy Cicada model if it exists locally
CICADA_MODEL_PATH="../Cicada/model/complete_model_package.joblib"
if [ -f "$CICADA_MODEL_PATH" ]; then
    echo "Found Cicada model, copying to model directory..."
    cp "$CICADA_MODEL_PATH" model/
    echo "Model copied successfully"
else
    echo "Warning: Cicada model not found at $CICADA_MODEL_PATH"
    echo "You need to train a model in Cicada and/or copy it manually to the model directory"
fi

# Add a reminder about Docker
echo "======================="
echo "DOCKER DEPLOYMENT NOTE"
echo "======================="
echo "When building a Docker image, ensure that the Dockerfile copies"
echo "both the 'model' directory and 'utils/cicada' directory."
echo ""
echo "Example Dockerfile additions:"
echo ""
echo "COPY model /app/model"
echo "COPY utils /app/utils"
echo ""
echo "Then rebuild your Docker image to include the Cicada model"
echo "and utility files."