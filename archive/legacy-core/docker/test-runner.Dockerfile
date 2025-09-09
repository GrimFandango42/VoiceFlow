# VoiceFlow Test Runner Docker Image
# This image provides a complete testing environment for VoiceFlow

FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    portaudio19-dev \
    python3-pyaudio \
    ffmpeg \
    git \
    curl \
    wget \
    sqlite3 \
    xvfb \
    x11-utils \
    dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements_testing.txt .
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements_testing.txt && \
    pip install --no-cache-dir pytest-xdist pytest-html pytest-cov && \
    pip install --no-cache-dir psutil matplotlib seaborn pandas numpy

# Copy application code
COPY . .

# Create test results directory
RUN mkdir -p /app/test_results

# Create entrypoint script
RUN cat > /app/test_entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Start virtual display for GUI tests
if [ "$ENABLE_XVFB" = "true" ]; then
    echo "Starting Xvfb..."
    Xvfb :99 -screen 0 1024x768x24 &
    export DISPLAY=:99
fi

# Run tests based on arguments
if [ "$1" = "unit" ]; then
    echo "Running unit tests..."
    python test_orchestrator.py --types unit --parallel --output-dir /app/test_results
elif [ "$1" = "integration" ]; then
    echo "Running integration tests..."
    python test_orchestrator.py --types integration --output-dir /app/test_results
elif [ "$1" = "e2e" ]; then
    echo "Running end-to-end tests..."
    python comprehensive_test_suite.py
elif [ "$1" = "performance" ]; then
    echo "Running performance tests..."
    python performance_regression_tests.py
elif [ "$1" = "security" ]; then
    echo "Running security tests..."
    python run_security_tests.py
elif [ "$1" = "comprehensive" ]; then
    echo "Running comprehensive test suite..."
    python test_orchestrator.py --output-dir /app/test_results
else
    echo "Running custom command: $@"
    exec "$@"
fi
EOF

RUN chmod +x /app/test_entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Set entrypoint
ENTRYPOINT ["/app/test_entrypoint.sh"]

# Default command
CMD ["comprehensive"]