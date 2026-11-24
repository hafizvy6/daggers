#!/usr/bin/env bash
# One-time (per fresh sandbox) browser install for the WS3 browser gates.
#   bash ops/setup_browser.sh
#
# The Playwright *module* is committed at ~/tools/playwright (12 MB) and the gates
# find it automatically — no env var needed.
#
# The Chromium *binary* is ~862 MB and is deliberately NOT stored: it lives in
# ~/.cache/ms-playwright, which the workspace snapshot excludes, and it would blow
# the snapshot size cap anyway. So it is re-downloaded here (about 90 MB).
set -uo pipefail

TOOLS="${PLAYWRIGHT_TOOLS:-$HOME/tools/playwright}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
PW="$TOOLS/node_modules/playwright"

if [ ! -d "$PW" ]; then
  echo "✗ Playwright module not found at $TOOLS"
  echo "  restore it with:  npm --prefix \"$TOOLS\" install"
  exit 1
fi

echo "Playwright module: $TOOLS"
echo "Browser cache:     $PLAYWRIGHT_BROWSERS_PATH"

exe="$(node -e "require('$PW').chromium.executablePath()" 2>/dev/null)"

if [ -n "$exe" ] && [ -x "$exe" ]; then
  echo "✓ Chromium found — checking it launches…"
  if node -e "
    const {chromium}=require('$PW');
    chromium.launch().then(b=>b.close()).then(()=>process.exit(0)).catch(()=>process.exit(1));
  " 2>/dev/null; then
    echo "✓ browser ready — run  bash ops/test_all.sh"
    exit 0
  fi
  echo "  binary present but won't launch — missing system libraries."
  echo "  on Debian/Ubuntu:  sudo apt-get install -y libcups2 libnss3 libatk1.0-0 libatk-bridge2.0-0 libxkbcommon0 libdrm2 libgbm1 libasound2"
  exit 1
fi

echo "→ downloading Chromium (about 90 MB)…"
node "$PW/cli.js" install chromium || exit 1

# the CLI prints a host-dependency warning on unsupported distros even when the
# browser works fine, so verify by actually launching rather than trusting output
echo "→ verifying it launches…"
if node -e "
  const {chromium}=require('$PW');
  chromium.launch().then(b=>b.close()).then(()=>process.exit(0)).catch(e=>{console.error(e.message.split('\n')[0]);process.exit(1)});
"; then
  echo "✓ browser ready — run  bash ops/test_all.sh"
else
  echo "✗ downloaded but won't launch — install the system libraries (see above)"
  exit 1
fi
