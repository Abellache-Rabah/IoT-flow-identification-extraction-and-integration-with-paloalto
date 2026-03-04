# ============================
# IoT Onboarding Tool
# Multi-stage Docker Build
# ============================

# ---- Stage 1: Build Frontend ----
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Runtime (Official Zeek image) ----
FROM zeek/zeek:6.0

USER root

# Install Python, pip, and tcpdump
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install ICSNPP OT protocol packages via zkg
RUN zkg autoconfig \
    && zkg install --force \
        icsnpp-modbus \
        icsnpp-dnp3 \
        icsnpp-bacnet \
        icsnpp-s7comm \
        icsnpp-enip \
        icsnpp-ethercat \
    ; exit 0

# Install Python dependencies
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy backend code
COPY backend/ ./

# Copy built frontend to static directory
COPY --from=frontend-build /app/frontend/dist ./static

# Create data directory
RUN mkdir -p /data/profiles

# Environment defaults
ENV DATA_DIR=/data
ENV CAPTURE_INTERFACE=eth0
ENV ZEEK_BIN=/usr/local/zeek/bin/zeek
ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080

EXPOSE 8080

CMD ["python3", "main.py"]
