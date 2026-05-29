#!/usr/bin/env bash
# OWASP Red Team Playground — single-command launcher.
#
# First run: creates a virtual env and installs deps.
# Every run: starts the Flask server and opens the browser.
#
# Usage:
#   ./start.sh             # default port 5050
#   PORT=8080 ./start.sh   # override port

set -euo pipefail

cd "$(dirname "$0")"

PY=${PYTHON:-python3}
PORT=${PORT:-5050}

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "ERROR: $PY is not on PATH. Install Python 3.10+ first." >&2
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo
    echo "  First-time setup: creating virtual environment..."
    "$PY" -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    echo "  Installing dependencies..."
    .venv/bin/pip install -q -r requirements.txt
    echo "  Done."
fi

URL="http://localhost:$PORT"

# Open the browser after a short delay (so the server is ready).
( sleep 1.2 && \
    if command -v open >/dev/null 2>&1; then open "$URL"; \
    elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"; \
    fi \
) &

export PORT
exec .venv/bin/python app.py
