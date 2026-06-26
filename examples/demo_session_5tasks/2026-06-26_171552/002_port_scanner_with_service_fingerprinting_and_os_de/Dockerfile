# FORGE OPSEC Container — port_scanner_with_service_fingerprinting
# Hardened Alpine-based deployment. Zero persistence. Zero attribution.
FROM python:3.12-alpine AS builder

# Minimal dependencies only
RUN apk add --no-cache gcc musl-dev libffi-dev
COPY generated.py /build/
COPY requirements.txt /build/ 2>/dev/null || true
RUN pip install --no-cache-dir --target=/build/deps -r /build/requirements.txt 2>/dev/null || true

# === Production stage ===
FROM python:3.12-alpine

# Security hardening
RUN addgroup -S forge && adduser -S forge -G forge && \
    apk add --no-cache tini libffi && \
    rm -rf /var/cache/apk/* /tmp/* /root/.cache

# Tor routing layer
RUN apk add --no-cache tor && \
    echo "SocksPort 0.0.0.0:9050" >> /etc/tor/torrc && \
    echo "DNSPort 0.0.0.0:5353" >> /etc/tor/torrc && \
    echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
# NOTE: raw_socket tools need --network=host or --cap-add=NET_RAW

# No shells in production (comment out for debugging)
# RUN rm -f /bin/sh /bin/ash /bin/bash

# Read-only filesystem + tmpfs for runtime data
WORKDIR /app
COPY --from=builder /build/generated.py /app/
COPY --from=builder /build/deps/ /app/deps/ 2>/dev/null || true
COPY port_scanner_with_service_fingerprinting /app/port_scanner_with_service_fingerprinting 2>/dev/null || true
ENV PYTHONPATH="/app/deps"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Sanitize environment — no operator identity leaks
ENV HOME=/app
ENV USER=forge
ENV HOSTNAME=localhost
ENV LANG=C.UTF-8
ENV TZ=UTC

# Disable core dumps
RUN echo "* hard core 0" >> /etc/security/limits.conf 2>/dev/null || true



# Drop to non-root
USER forge

# Entrypoint: tini for signal handling + proper PID 1
ENTRYPOINT ["tini", "--"]
CMD ["python3", "/app/generated.py"]
