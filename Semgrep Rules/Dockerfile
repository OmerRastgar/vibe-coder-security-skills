FROM python:3.12-alpine

ARG TRUFFLEHOG_VERSION=3.88.16

RUN apk add --no-cache git curl

RUN echo "Installing semgrep..." && pip install --no-cache-dir semgrep

RUN echo "Installing checkov..." && pip install --no-cache-dir checkov

RUN echo "Installing TruffleHog ${TRUFFLEHOG_VERSION}..." && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64)  TH_ARCH="amd64" ;; \
      aarch64) TH_ARCH="arm64" ;; \
      *)       echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" | \
    tar xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

RUN mkdir -p /app

COPY ["Semgrep Rules/rules/", "/app/rules/"]
COPY ["Semgrep Rules/scanners/", "/app/scanners/"]
COPY ["Semgrep Rules/server.py", "/app/server.py"]
COPY ["Semgrep Rules/requirements.txt", "/app/requirements.txt"]

RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 8080
WORKDIR /app
CMD ["sh", "-c", "exec gunicorn --bind \"0.0.0.0:${PORT:-8080}\" --timeout 600 --workers 1 --threads 4 server:app"]
