# Elite Recovery OSINT Backend
# Python service with comprehensive OSINT tools

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies + Playwright browser dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    # Playwright/Chromium dependencies
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    fonts-liberation \
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

# Install Playwright and Chromium browser for anti-bot bypass
RUN pip install --no-cache-dir playwright \
    && playwright install chromium --with-deps || echo "Playwright install failed, using fallback scrapers"

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
