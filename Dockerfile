FROM python:3.12-alpine

LABEL maintainer="antigravity"
LABEL description="SecureVault: 4096-Bit Dual-Key Split Encryption Server"

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY code_generator.py crypto_engine.py storage.py email_service.py monitor_server.py server.py ./

# Create data directory and unprivileged user
RUN mkdir -p /app/data/vault && \
    adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

VOLUME ["/app/data/vault"]

EXPOSE 8080 8081

HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python3", "server.py"]
CMD ["--port", "8080", "--host", "0.0.0.0", "--storage-dir", "/app/data/vault"]
