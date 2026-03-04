FROM python:3.13-slim AS base

RUN groupadd -r proxyapp && useradd -r -g proxyapp -d /app proxyapp

# Install Node.js 22 LTS
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Build viewer
COPY viewer/package.json viewer/package-lock.json* viewer/
RUN cd viewer && npm ci
COPY viewer/ viewer/
RUN cd viewer && npx tsc
RUN cp -r viewer/src/public viewer/public
RUN cd viewer && npm prune --production

# Copy proxy source
COPY proxy.py mitm_certs.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

RUN mkdir -p /app/certs/hosts && chown -R proxyapp:proxyapp /app
# Ensure the default log file is writable by any UID (compose user override)
RUN touch /tmp/proxy.log && chmod 666 /tmp/proxy.log

USER proxyapp

EXPOSE 8080 9999

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.create_connection(('127.0.0.1',8080),2); s.close()" \
     && node -e "const h=require('http');h.get('http://127.0.0.1:9999/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

ENTRYPOINT ["./entrypoint.sh"]
CMD ["--mitm", "--no-verify"]
