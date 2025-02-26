#!/bin/bash

echo "=== SnoopyIDS Fix & Rebuild Script ==="
echo "This script fixes the entropy and feature count issues"
echo "and rebuilds the Docker container."
echo ""

# Run the integration script
echo "Step 1: Running integration script..."
python integrate.py

# Make sure we explicitly install scipy 
echo ""
echo "Step 2: Verifying Dockerfile has scipy..."
if grep -q "pip install.*scipy" Dockerfile; then
    echo "✅ Dockerfile already includes scipy"
else
    echo "⚠️ Adding scipy to Dockerfile..."
    sed -i.bak 's/pip install --no-cache-dir -r requirements.txt/pip install --no-cache-dir -r requirements.txt scipy/' Dockerfile
    echo "✅ Updated Dockerfile"
fi

# Rebuild the Docker container
echo ""
echo "Step 3: Rebuilding Docker container..."
docker-compose down
docker-compose build --no-cache
docker-compose up -d

echo ""
echo "Process complete! Check the logs with: docker-compose logs -f"