FROM python:3.13-slim

# Install nmap, ca-certificates and deps
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Support ASI_DATA_DIR for SQLite + Fernet key at rest
ENV ASI_DATA_DIR=/app/data

# Expose FastAPI port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]