#!/usr/bin/env bash
# Daggers · freeze the demo into ONE portable folder OUTSIDE the repo
# (so the repo stays lean, and the parachute can be copied to a USB stick as-is).
set -euo pipefail
cd "$(dirname "$0")/../.."
STAMP=$(date +%Y%m%d-%H%M)
OUT="${1:-$HOME}/daggers-snapshot-$STAMP"
mkdir -p "$OUT"

cp -r web "$OUT/app"
cp -r backend/seed/fixtures "$OUT/fixtures"
cp -r backend/seed/evidence "$OUT/evidence"
cp ops/demo/RUNOFSHOW.md ops/demo/DEMO_MODE.md "$OUT/"
cp docs/UI-KIT.md ops/checklist.md "$OUT/"

python3 - "$OUT" <<'PYEOF' >> "$OUT/SNAPSHOT.txt"
import json, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
print("Daggers demo snapshot")
print("when:", __import__("datetime").datetime.now().isoformat(timespec="seconds"))
print("commit:", subprocess.run(["git","rev-parse","--short","HEAD"],capture_output=True,text=True).stdout.strip() or "no-git")
feed = json.loads((out/"fixtures/feed.json").read_text())
reps = json.loads((out/"fixtures/reports.json").read_text())
print("findings:", len(feed["findings"]), "| reports:", len(reps["reports"]),
      "| evidence jpgs:", len(list((out/"evidence").glob("*.jpg"))))
print("run:", f"python3 -m http.server -d {out}/app 8000  →  http://localhost:8000/?mode=demo#/feed")
PYEOF
echo "→ $OUT"
du -sh "$OUT"
