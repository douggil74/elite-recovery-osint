# Elite Recovery OSINT Backend
# With Playwright for web scraping

FROM python:3.11-slim

WORKDIR /app

# Install system deps including Playwright requirements
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    gnupg \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install OSINT tools and Playwright
RUN pip install --no-cache-dir \
    sherlock-project \
    socialscan \
    holehe \
    playwright

# Install Playwright browsers (chromium only to save space)
RUN playwright install chromium

# Copy app
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
