#!/bin/bash

echo "Rebuilding SnoopyIDS Docker container with fixes..."

# Stop and remove existing containers
docker-compose down

# Rebuild without cache
docker-compose build --no-cache

# Start the services
docker-compose up -d

echo "SnoopyIDS has been rebuilt and restarted."
echo "Check logs with: docker-compose logs"