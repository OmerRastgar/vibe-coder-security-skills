FROM alpine:3.20

ARG NUCLEI_VERSION=3.3.9

# Install system dependencies + nuclei binary in one layer
RUN apk add --no-cache python3 py3-pip curl unzip && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64)  NUCLEI_ARCH="amd64" ;; \
      aarch64) NUCLEI_ARCH="arm64" ;; \
      armv7l)  NUCLEI_ARCH="armv7" ;; \
      *)       echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei.zip /tmp/nuclei

# Clone nuclei-templates (largest layer — cached unless templates change)
RUN curl -sSL https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz | \
    tar xz -C /opt && \
    mv /opt/nuclei-templates-main /opt/nuclei-templates

# Copy application files
COPY ["Nuclei Templates/", "/opt/templates/"]
COPY ["Nuclei Templates/server.py", "/app/server.py"]
COPY ["Nuclei Templates/ai_processor.py", "/app/ai_processor.py"]

# Install Python dependencies
RUN pip3 install --break-system-packages --no-cache-dir flask flask-cors

EXPOSE 8080
WORKDIR /app
CMD ["sh", "-c", "exec python3 server.py"]
