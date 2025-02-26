FROM python:3.9-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy fix_feature_extractor.py first so we can run it
COPY fix_feature_extractor.py .

# Copy the rest of the application
COPY . .

# Create a directory for logs
RUN mkdir -p logs && chmod 777 logs

# Make sure WAF protocol buffers are compiled
RUN pip install grpcio-tools
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. waf.proto

# Apply the fixes to handle both entropy and feature count issues
RUN python fix_feature_extractor.py

# Set Python to run in unbuffered mode
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command
CMD ["python", "-u", "app.py"]