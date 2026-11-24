#!/usr/bin/env bash
# Daggers · WS3 local dev runner (not a product artifact — a convenience script)
#   serve the PWA + WS3 routers on one origin, exactly like the venue laptop will.
#
#   bash ops/dev.sh          → http://localhost:8080
#   bash ops/dev.sh demo     → same, with DEMO_MODE forced on
set -euo pipefail
cd "$(dirname "$0")/.."

# prefer the venv made by ops/setup.sh, else the system python
if [ -n "${PYTHON:-}" ]; then
  PY="$PYTHON"
elif [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif [ -x ".venv/Scripts/python.exe" ]; then
  PY=".venv/Scripts/python.exe"
else
  PY="python3"
fi

PORT="${PORT:-8080}"
case "${1:-}" in
  demo) export DEMO_MODE=1 ;;
esac

# fail loudly and usefully if the packages aren't there yet
"$PY" -c "import fastapi, uvicorn" 2>/dev/null || {
  echo "✗ python packages missing. Run:  bash ops/setup.sh"
  exit 1
}

# 0.0.0.0 is "listen on every interface" — it is NOT a URL a browser can open.
# On Linux curl tolerates it; Chrome/Edge on Windows reject it with
# ERR_ADDRESS_INVALID. So we bind 0.0.0.0 but always tell the human localhost.
# NOTE: `|| true` is required — grep returns 1 when nothing matches, and with
# `set -e` + `pipefail` that would silently kill this script.
LAN_IP="$( { hostname -I 2>/dev/null || true; } | tr ' ' '\n' | grep -vE '^(169\.254\.|)$' | head -1 || true)"

cat <<BANNER

  Daggers · WS3 — demo server starting
  ───────────────────────────────────────────────────────────
  Open in your browser:   http://localhost:${PORT}

  (leave this terminal running; Ctrl+C to stop)

BANNER

if grep -qi microsoft /proc/version 2>/dev/null; then
  cat <<'WSLNOTE'
  WSL detected — open the link in your WINDOWS browser. localhost is
  forwarded automatically; if it isn't, use the address printed below.
WSLNOTE
  [ -n "$LAN_IP" ] && echo "  WSL address:            http://${LAN_IP}:${PORT}"
  echo
fi

if [ -n "$LAN_IP" ]; then
  echo "  Same network / phone:   http://${LAN_IP}:${PORT}"
  echo "  ───────────────────────────────────────────────────────────"
  echo
fi

exec "$PY" -m uvicorn backend.app.server:app --host 0.0.0.0 --port "$PORT"
