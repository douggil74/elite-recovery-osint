# Elite Recovery OSINT Backend
# Python service with comprehensive OSINT tools

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install core OSINT tools (username search)
RUN pip install --no-cache-dir \
    sherlock-project \
    maigret \
    socialscan \
    social-analyzer

# Install email tools
RUN pip install --no-cache-dir \
    holehe \
    h8mail

# Install theHarvester from GitHub (PyPI version is abandoned at 0.0.1)
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git

# Install Instagram tools
RUN pip install --no-cache-dir \
    instaloader \
    toutatis

# Install phone tools
RUN pip install --no-cache-dir \
    ignorant

# Install web/domain tools
RUN pip install --no-cache-dir \
    waybackpy \
    dnspython \
    python-whois

# Install document/metadata tools
RUN pip install --no-cache-dir \
    ExifRead \
    PyPDF2 \
    python-docx

# Install geolocation tools
RUN pip install --no-cache-dir \
    geopy \
    ip2geotools

# Install search tools
RUN pip install --no-cache-dir \
    duckduckgo-search \
    googlesearch-python

# Install optional tools (may fail)
RUN pip install --no-cache-dir blackbird || echo "blackbird install failed, skipping"
RUN pip install --no-cache-dir snscrape || echo "snscrape install failed, skipping"
RUN pip install --no-cache-dir ghunt || echo "ghunt install failed, skipping"

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
