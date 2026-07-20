FROM python:3.12-slim

ARG TRUFFLEHOG_VERSION=3.88.16

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Install all Python packages in one layer (reduces image size significantly)
RUN pip install --no-cache-dir \
    semgrep \
    checkov \
    flask \
    gunicorn

# Install TruffleHog binary
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64)  TH_ARCH="amd64" ;; \
      aarch64) TH_ARCH="arm64" ;; \
      *)       echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" | \
    tar xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

ENV PATH="/root/.local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

# Pre-create app directory
RUN mkdir -p /app

# Copy application files (these change more often, so they're last for better caching)
COPY ["rules/", "/app/rules/"]
COPY ["scanners/", "/app/scanners/"]
COPY ["server.py", "/app/server.py"]
COPY ["ai_processor.py", "/app/ai_processor.py"]

EXPOSE 8080
WORKDIR /app
CMD ["sh", "-c", "exec python3 server.py"]
