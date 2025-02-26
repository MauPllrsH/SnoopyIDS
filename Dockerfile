FROM python:3.9-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a directory for logs
RUN mkdir -p logs && chmod 777 logs

# Make sure WAF protocol buffers are compiled
RUN pip install grpcio-tools
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. waf.proto

# Verify the proto files exist
RUN ls -la waf_pb2*.py

# Verify imports work correctly and test our entropy module
RUN python dockerfile_imports.py
RUN python -c "import entropy; print('entropy module loaded')"

# Make a pre-compiled version of startup.py to ensure it works
RUN python -m py_compile startup.py

# Make entropy.py executable
RUN chmod +x entropy.py
RUN chmod +x startup.py

# Copy the preload and utility scripts to the container
COPY preload.py .
COPY entropy.py .
COPY feature_fix.py . 
COPY docker_start.sh .

# Make sure scripts are executable
RUN chmod +x preload.py
RUN chmod +x docker_start.sh

# Set Python to run in unbuffered mode
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command
CMD ["./docker_start.sh"]