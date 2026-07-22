# Build from project root: docker build -t openvoicechat-server -f server/Dockerfile .

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/main.py .
COPY shared/ /app/shared/

# Remove any __pycache__ copied from host (e.g. Python 3.13 .pyc)
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

EXPOSE 9090/tcp 9091/tcp

# -B: don't write .pyc files at runtime (prevents Python 3.11 __pycache__)
CMD ["python", "-B", "main.py"]