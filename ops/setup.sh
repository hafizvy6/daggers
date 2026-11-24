#!/usr/bin/env bash
# Daggers · one-command setup for a machine that has never run this before.
#   bash ops/setup.sh
#
# Installs the Python packages the tests need. It does NOT install Node or Playwright:
# those are separate, bigger, and you may already have them (the gates find Playwright
# wherever it is — global install, Homebrew, node_modules, or ~/tools).
#
# Works on Linux, macOS and WSL. On native Windows, run this inside WSL:
#   wsl  →  cd /mnt/c/Users/<you>/Documents/daggers/daggers  →  bash ops/setup.sh
set -uo pipefail
cd "$(dirname "$0")/.."

echo "── Daggers setup ──────────────────────────────────────────"
echo "python: $(python3 --version 2>&1)  ($(command -v python3))"

# --- 1. Python packages -----------------------------------------------------
echo
echo "── installing python packages"
# Prefer a venv: modern Debian/Ubuntu (and WSL's stock python) refuse system-wide
# pip installs with "externally-managed-environment".
if python3 -c "import fastapi, httpx, pytest, pydantic" 2>/dev/null; then
  echo "✓ already installed — nothing to do"
else
  if python3 -m venv .venv 2>/dev/null; then
    echo "  using a venv at .venv/ (keeps your system python clean)"
    ./.venv/bin/python -m pip install --quiet --upgrade pip
    ./.venv/bin/python -m pip install --quiet -r backend/requirements.txt || {
      echo "✗ pip install failed — scroll up for the reason"; exit 1; }
    echo "✓ installed into .venv"
    echo
    echo "  NOTE: activate it before running the tests:"
    echo "      source .venv/bin/activate"
    echo "  ...or just run everything through it:"
    echo "      .venv/bin/python ops/check_i18n.py"
  elif python3 -m pip install --quiet -r backend/requirements.txt 2>/dev/null; then
    echo "✓ installed system-wide"
  elif python3 -m pip install --quiet --user -r backend/requirements.txt; then
    echo "✓ installed for this user"
  elif python3 -m pip install --quiet --user --break-system-packages -r backend/requirements.txt; then
    echo "✓ installed for this user (--break-system-packages)"
  else
    echo "✗ could not install the python packages."
    echo "  try:  python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt"
    exit 1
  fi
fi

# --- 2. Node -----------------------------------------------------------------
echo
echo "── checking node"
if command -v node >/dev/null 2>&1; then
  echo "✓ node $(node --version) at $(command -v node)"
else
  echo "✗ node not found — the syntax check and the 3 browser gates need it."
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "  You're in WSL. Node installed on Windows is NOT visible here — install it inside WSL:"
  else
    echo "  Install it with:"
  fi
  echo "      curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -"
  echo "      sudo apt-get install -y nodejs"
  echo "  macOS:   brew install node"
  echo "  Windows: winget install OpenJS.NodeJS.LTS   (native, not WSL — then reopen the terminal)"
  echo "  Without node: gate 1 and all 37 python tests still run"
  echo "  ( DAGGERS_ALLOW_PARTIAL=1 bash ops/test_all.sh )"
fi

# --- 3. Playwright (module + browser) ---------------------------------------
echo
echo "── checking playwright"
if command -v node >/dev/null 2>&1; then
  PW_HOME="$HOME/tools/playwright/node_modules/playwright"
  if [ -n "${PLAYWRIGHT_MODULE:-}" ] && node -e "require('$PLAYWRIGHT_MODULE')" 2>/dev/null; then
    echo "✓ playwright module found (PLAYWRIGHT_MODULE)"
    PW_REQ="$PLAYWRIGHT_MODULE"
  elif node -e "require('playwright')" 2>/dev/null; then
    echo "✓ playwright module found (local/global)"
    PW_REQ="playwright"
  elif node -e "require('$(npm root -g 2>/dev/null)/playwright')" 2>/dev/null; then
    echo "✓ playwright module found (global npm)"
    PW_REQ="$(npm root -g)/playwright"
  elif node -e "require('$PW_HOME')" 2>/dev/null; then
    echo "✓ playwright module found (~/tools/playwright)"
    PW_REQ="$PW_HOME"
  else
    PW_REQ=""
  fi
  if [ -n "$PW_REQ" ]; then
    if node -e "require('$PW_REQ').chromium.launch().then(b=>b.close()).then(()=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null; then
      echo "✓ chromium launches — the browser gates will work"
    else
      echo "… chromium missing or won't launch. Install it with:"
      echo "      npx playwright install chromium"
      echo "  (on Linux/WSL, if it still won't launch:  sudo npx playwright install-deps chromium)"
    fi
  else
    echo "… playwright module not found. Install it with:"
    echo "      npm i -g playwright && npx playwright install chromium"
  fi
fi

echo
echo "── done. Next:"
echo "    bash ops/dev.sh          # run the app  → http://localhost:8080"
echo "    bash ops/test_all.sh     # prove it works"
