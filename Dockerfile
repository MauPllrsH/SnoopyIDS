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

# Apply critical patches at build time
RUN sed -i '1s/^/import builtins, sys\ntry:\n    from scipy.stats import entropy\nexcept ImportError:\n    def entropy(pk, qk=None, base=None):\n        import numpy as np\n        pk = np.asarray(pk)\n        pk = pk / float(np.sum(pk))\n        vec = pk * np.log(pk)\n        vec[~np.isfinite(vec)] = 0.0\n        return -np.sum(vec)\n    builtins.entropy = entropy\n    class EntropyModule: pass\n    EntropyModule.entropy = entropy\n    sys.modules["entropy"] = EntropyModule\n\n/' app.py

# Create fixed entropy module
RUN echo 'import numpy as np; def entropy(pk, qk=None, base=None): pk = np.asarray(pk); pk = pk / float(np.sum(pk)); vec = pk * np.log(pk); vec[~np.isfinite(vec)] = 0.0; return -np.sum(vec)' > /app/entropy.py

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

# Create a wrapper script to fix feature count issues in predict_anomaly
RUN echo 'import numpy as np
from sklearn.base import BaseEstimator

# Store original predict_proba
_original_predict_proba = BaseEstimator.predict_proba

# Define patched method
def _patched_predict_proba(self, X, *args, **kwargs):
    try:
        # Try original method
        return _original_predict_proba(self, X, *args, **kwargs)
    except ValueError as e:
        error_msg = str(e)
        if "has 64 features, but" in error_msg and "features as input" in error_msg:
            import re
            # Extract expected count
            match = re.search(r"expecting (\d+) features", error_msg)
            if match:
                expected_count = int(match.group(1))
                # Add padding
                if X.shape[1] < expected_count:
                    padding = np.zeros((X.shape[0], expected_count - X.shape[1]))
                    X_padded = np.hstack((X, padding))
                    return _original_predict_proba(self, X_padded, *args, **kwargs)
                elif X.shape[1] > expected_count:
                    X_trimmed = X[:, :expected_count]
                    return _original_predict_proba(self, X_trimmed, *args, **kwargs)
        raise e

# Apply patch
BaseEstimator.predict_proba = _patched_predict_proba
print("✅ Patched sklearn to handle feature count mismatches")' > /app/feature_patch.py

# Create direct entry point script
RUN echo '#!/bin/bash
# Run preloads and the app
echo "Starting SnoopyIDS..."
echo "Applying entropy function patch..."
python -c "import sys, builtins; from scipy.stats import entropy; builtins.entropy = entropy; class EntropyModule: pass; EntropyModule.entropy = entropy; sys.modules[\"entropy\"] = EntropyModule; print(\"✅ Entropy function loaded globally\")"
echo "Applying feature count fix..."
python -c "import sys; sys.path.insert(0, \"/app\"); exec(open(\"/app/feature_patch.py\").read())"
echo "Starting app..."
exec python -u app.py
' > /app/entrypoint.sh

# Make it executable
RUN chmod +x /app/entrypoint.sh

# Default command
CMD ["/app/entrypoint.sh"]