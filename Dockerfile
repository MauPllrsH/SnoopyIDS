FROM python:3.9-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt scipy

# Copy the application
COPY . .

# Create a directory for logs
RUN mkdir -p logs && chmod 777 logs

# Make sure WAF protocol buffers are compiled
RUN pip install grpcio-tools
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. waf.proto

# Verify the proto files exist
RUN ls -la waf_pb2*.py

# Set Python to run in unbuffered mode
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Make the fix script executable
RUN chmod +x fix.py

# Run the fix script and then start the app
CMD ["sh", "-c", "python -u fix.py && python -u app.py"]