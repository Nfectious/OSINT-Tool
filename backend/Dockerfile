FROM python:3.11-slim

WORKDIR /app

# System deps for OSINT tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    whois \
    dnsutils \
    nmap \
    exiftool \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Sherlock
RUN pip install sherlock-project

# Install Holehe
RUN pip install holehe

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8400

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8400", "--reload"]
