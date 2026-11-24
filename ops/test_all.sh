#!/usr/bin/env bash
# Daggers · WS3 full test run — gates + unit + API + syntax + browser behaviour.
#   bash ops/test_all.sh
#
# Needs: python3 with the backend requirements, node, and Playwright (module + Chromium)
# for the browser gates. Everything is checked up front so you get one clear list of
# what is missing instead of a wall of tracebacks.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"

fail=0
skipped=0
run() { local label="$1"; shift; echo; echo "── $label"; "$@"; local rc=$?; [ $rc -ne 0 ] && fail=1; return 0; }

# ---------------------------------------------------------------- preflight
echo "══ preflight ══"
missing=0

# prefer a venv made by ops/setup.sh — otherwise `python3` may lack the packages
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif [ -x ".venv/Scripts/python.exe" ]; then
  PY=".venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "✗ python3 not found on PATH — install Python 3.10 or newer"
  echo "  then:  pip install -r backend/requirements.txt"
  exit 1
fi
echo "  python: $($PY --version 2>&1)  ($(command -v $PY))"

# Python packages the tests import
pkg_report=$($PY - <<'EOF' 2>&1
import importlib.util as u
want = [("fastapi","fastapi"), ("httpx","httpx"), ("pytest","pytest"), ("pydantic","pydantic")]
missing = [label for label, mod in want if u.find_spec(mod) is None]
print("MISSING:" + ",".join(missing) if missing else "OK")
EOF
)
if [ "$pkg_report" = "OK" ]; then
  echo "  python packages: ok"
else
  echo "✗ missing python packages: ${pkg_report#MISSING:}"
  echo "  fix:  $PY -m pip install -r backend/requirements.txt"
  missing=1
fi

# Node (only the browser gates need it)
if command -v node >/dev/null 2>&1; then
  echo "  node: $(node --version)  ($(command -v node))"
  NODE_OK=1
else
  echo "✗ node not found on PATH — needed for the syntax check and the 3 browser gates"
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "  WSL detected. Node on Windows is NOT visible inside WSL — install it here:"
    echo "      curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -"
    echo "      sudo apt-get install -y nodejs"
  else
    echo "  macOS:    brew install node"
    echo "  Ubuntu:   curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs"
    echo "  Windows:  winget install OpenJS.NodeJS.LTS"
  fi
  NODE_OK=0
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  cat <<'MSG'

── stopping before running anything (nothing has been changed).
   Install what's listed above, then run this again.

   In a hurry, or only after the Python side? Run what can run right now:
       DAGGERS_ALLOW_PARTIAL=1 bash ops/test_all.sh
   The browser gates will be reported as skipped, not failed.
MSG
  if [ "${DAGGERS_ALLOW_PARTIAL:-0}" = "1" ]; then
    echo "   (DAGGERS_ALLOW_PARTIAL=1 — running whatever can run)"
  else
    exit 1
  fi
fi

# Playwright: the module may be anywhere sensible; the browser is separate.
if [ -z "${PLAYWRIGHT_MODULE:-}" ] && [ -d "$HOME/tools/playwright/node_modules/playwright" ]; then
  export PLAYWRIGHT_MODULE="$HOME/tools/playwright/node_modules/playwright"
fi

# ---------------------------------------------------------------- gates
run "gate 1 · i18n / no hardcoded text / no demo data in code / no raw hex / logical CSS" \
    $PY ops/check_i18n.py
run "unit · AI rules + fixture contracts" $PY -m pytest backend/tests -q

if [ "$NODE_OK" -eq 1 ]; then
  run "static · every ES module parses" node ops/check_syntax.mjs
else
  echo; echo "── static · every ES module parses"; echo "   SKIPPED (node not installed)"
  skipped=1
fi

echo; echo "── starting the dev server for the browser gates"
$PY -m uvicorn backend.app.server:app --host 127.0.0.1 --port 8080 > /tmp/daggers-test-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
UP=0
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null http://127.0.0.1:8080/api/status 2>/dev/null; then UP=1; break; fi
  if command -v curl >/dev/null 2>&1; then sleep 0.5; else sleep 0.5; fi
done
if [ "$UP" -ne 1 ]; then
  echo "✗ the API did not come up on :8080 — see /tmp/daggers-test-server.log"
  tail -15 /tmp/daggers-test-server.log 2>/dev/null
  exit 1
fi

if [ "$NODE_OK" -eq 1 ]; then
  run "gate 2 · a11y (contrast · tap targets · RTL · keyboard · overflow)" \
      node ops/check_a11y.mjs http://127.0.0.1:8080
  run "gate 3 · purity + offline DEMO story" node ops/check_offline.mjs http://127.0.0.1:8080
  run "gate 4 · UI behaviour" node ops/check_ui.mjs http://127.0.0.1:8080
else
  echo; echo "── gates 2–4 · a11y · purity/offline · UI behaviour"; echo "   SKIPPED (node not installed)"
fi

echo
if [ "$fail" -eq 0 ] && [ "$skipped" -eq 0 ]; then
  echo "✅ WS3 — all gates and tests passed"
elif [ "$fail" -eq 0 ]; then
  echo "⚠️  WS3 — everything that ran passed, but some checks were SKIPPED (node missing)."
  echo "    This is not a full verification. Install node and run again for the real thing."
else
  echo "❌ WS3 — something failed above"
fi
exit $fail
