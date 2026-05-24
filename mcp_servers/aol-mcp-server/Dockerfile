FROM python:3.12-slim

WORKDIR /srv

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV MCP_TRANSPORT=sse \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8765 \
    LOG_LEVEL=INFO

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(2); \
    sys.exit(0) if s.connect_ex(('127.0.0.1',8765))==0 else sys.exit(1)" || exit 1

CMD ["python", "-u", "server.py"]
