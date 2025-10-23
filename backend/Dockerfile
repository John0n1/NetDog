FROM python:3.11-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    iputils-ping \
    speedtest-cli \
    iproute2 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user (but with network capabilities)
RUN useradd -m -u 1000 netdog && \
    chown -R netdog:netdog /app

# Note: We'll need NET_ADMIN and NET_RAW capabilities for network operations
# These are set in docker-compose.yml

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
