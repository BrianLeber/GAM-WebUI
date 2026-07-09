# GAM-WebUI Production Container
#
# Single container serves all clients. Per-client GAM credential directories
# are mounted as volumes at runtime — credentials never live in the image.
#
# GAM binary strategy:
#   Mount from host read-only: -v /path/to/gam7:/opt/gam7:ro
#   This means a GAM update on the host applies to all clients immediately.
#   No need to rebuild the image for GAM version bumps.
#
# Data directory structure (mount at /data):
#   /data/config.yaml          — app config (copy from config.example.yaml)
#   /data/db.sqlite            — SQLite database (auto-created on first run)
#   /data/logs/                — audit logs and termination records
#   /data/clients/
#     {client_id}/
#       gam-config-admin/      — full-scope GAM credentials
#       gam-config-helpdesk/   — reduced-scope GAM credentials
#
# Build:
#   docker build -t gam-webui .
#
# Run (development):
#   docker run -p 8000:8000 \
#     -v /home/user/bin/gam7:/opt/gam7:ro \
#     -v $(pwd)/data:/data \
#     -e GAM_WEBUI_CONFIG=/data/config.yaml \
#     gam-webui
#
# See docker-compose.yml for production deployment.

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY cli/      ./cli/

# GAM binary and client configs are mounted at runtime
ENV GAM_PATH=/opt/gam7/gam
ENV GAM_WEBUI_CONFIG=/data/config.yaml

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
