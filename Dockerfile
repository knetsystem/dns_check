# Dockerfile
FROM python:3.12-slim

# Make a non-root user
RUN useradd -m app
WORKDIR /app

# Install deps (dnspython is pure-Python, so no build tools needed)
RUN pip install --no-cache-dir dnspython

# Copy your script (adjust name/path as needed)
COPY dns-test.py /app/dns-test.py

# Run as non-root
USER app

# Default: run once and exit (good for textfile exporter via cron/k8s/sidecar)
CMD ["python", "/app/dns-test.py"]

