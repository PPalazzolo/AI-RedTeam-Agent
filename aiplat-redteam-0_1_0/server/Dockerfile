# Hosted aiplat-redteam MCP server.
#
# Build from the REPO ROOT (the folder that contains both `redteam/` and
# `aiplat-redteam-0_1_0/`) so the red team engine can be copied in:
#
#   docker build -f aiplat-redteam-0_1_0/server/Dockerfile -t aiplat-redteam .
#   docker run -p 8000:8000 aiplat-redteam
#
# The MCP endpoint is then served at http://<host>:8000/mcp
FROM python:3.12-slim

WORKDIR /app

# Red team engine (agentic_redteam.py, garak_suite.py, target bridge, etc.).
COPY redteam/ /app/redteam/
# This plugin's server code.
COPY aiplat-redteam-0_1_0/server/ /app/server/

RUN pip install --no-cache-dir -r /app/server/requirements.txt
# Uncomment to enable the garak suite (adds GARAK-* findings; larger image):
# RUN pip install --no-cache-dir "garak>=0.17"

ENV REDTEAM_PKG_DIR=/app/redteam \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000
CMD ["python", "/app/server/redteam_mcp_server.py"]
