FROM alpine:3.20

ARG NUCLEI_VERSION=3.3.9

RUN apk add --no-cache python3 py3-pip curl unzip

RUN echo "Installing nuclei ${NUCLEI_VERSION}..." && \
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

RUN echo "Cloning nuclei-templates..." && \
    wget -qO- https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz | \
    tar xz -C /opt && \
    mv /opt/nuclei-templates-main /opt/nuclei-templates

COPY "Nuclei Templates/" /opt/templates/
COPY "Nuclei Templates/server.py" /app/server.py
COPY "Nuclei Templates/requirements.txt" /app/requirements.txt

RUN pip3 install --break-system-packages --no-cache-dir -r /app/requirements.txt

EXPOSE 5000
WORKDIR /app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "300", "server:app"]
