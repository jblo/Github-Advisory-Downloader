# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY github_advisory_downloader.py .
COPY README.md .
COPY LICENSE .

# Create output directory
RUN mkdir -p /app/output

# Set environment variables
ENV PYTHONPATH=/app
ENV OUTPUT_DIR=/app/output

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('https://api.github.com', timeout=5)" || exit 1

# Default command
CMD ["python", "github_advisory_downloader.py", "--output-dir", "/app/output"]

---

# docker-compose.yml
version: '3.8'

services:
  github-advisory-downloader:
    build: .
    container_name: github-advisory-downloader
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN:-}
      - OUTPUT_DIR=/app/output
    volumes:
      - ./output:/app/output
      - ./logs:/app/logs
    command: >
      python github_advisory_downloader.py 
      ${GITHUB_TOKEN:+--token ${GITHUB_TOKEN}} 
      --output-dir /app/output
    restart: "no"
    networks:
      - advisory-network

  # Optional: Add a simple web server to browse the results
  file-server:
    image: nginx:alpine
    container_name: advisory-file-server
    ports:
      - "8080:80"
    volumes:
      - ./output:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - github-advisory-downloader
    networks:
      - advisory-network

networks:
  advisory-network:
    driver: bridge

volumes:
  advisory-data:
    driver: local

---

# nginx.conf (for file server)
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;
        
        # Enable directory browsing
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
        
        # Handle CSV files
        location ~ \.csv$ {
            add_header Content-Type text/plain;
        }
        
        # Handle JSON files
        location ~ \.json$ {
            add_header Content-Type application/json;
        }
        
        # Handle ZIP files
        location ~ \.zip$ {
            add_header Content-Type application/zip;
        }
    }
}
