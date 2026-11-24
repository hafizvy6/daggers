#!/usr/bin/env python3
"""WS3 gate 1 — no hardcoded user-visible strings; EN/AR key parity.

Fails (exit 1) if:
  · a views/components file contains user-facing English text in the DOM API
    (`text: "…"`, `.textContent = "…"`) that is not routed through t()
  · en.json and ar.json key sets differ
  · a t("…") key used in code is missing from the catalogs
"""
from __future__ import annotations
import json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
fail = []

en = json.loads((WEB / "js/i18n/en.json").read_text(encoding="utf-8"))
ar = json.loads((WEB / "js/i18n/ar.json").read_text(encoding="utf-8"))

def flat(d, pre=""):
    out = {}
    for k, v in d.items():
        key = f"{pre}{k}"
        if isinstance(v, dict):
            out.update(flat(v, f"{key}."))
        else:
            out[key] = v
    return out

fen, far = flat(en), flat(ar)
for k in fen.keys() - far.keys():
    fail.append(f"ar.json missing key: {k}")
for k in far.keys() - fen.keys():
    fail.append(f"en.json missing key: {k}")
for k, v in fen.items():
    if k in far and not str(far[k]).strip():
        fail.append(f"ar.json empty value: {k}")

# ---- hardcoded strings in JS (allow: file paths, CSS, classes, numbers) ----
ALLOW = re.compile(
    r"^(?:[a-z0-9\-_./#\[\]=&?%+:{}]*|"          # tokens, paths, symbols
    r"[a-z0-9\-_]+(?:\s+[a-z0-9\-_]+){0,2})$",   # tiny tokens like "GET"
    re.I)
TEXT_PATTERNS = [
    re.compile(r'\btext:\s*"([^"{]{2,})"'),
    re.compile(r'\.textContent\s*=\s*"([^"{]{2,})"'),
    re.compile(r'\bhtml:\s*"([^"{]{2,})"'),
]
for f in sorted((WEB / "js").rglob("*.js")):
    src = f.read_text(encoding="utf-8")
    # strip comments + template literals we deliberately stream (AI text)
    lines = src.splitlines()
    for i, line in enumerate(lines, 1):
        if line.strip().startswith(("//", "*", "/*")):
            continue
        if "icons" in line or "svg" in line.lower() or "logoMark" in line or "mascot" in line:
            continue
        for pat in TEXT_PATTERNS:
            for m in pat.finditer(line):
                val = m.group(1)
                if ALLOW.match(val):
                    continue
                fail.append(f"{f.relative_to(ROOT)}:{i}: hardcoded text → {val!r}")

# ---- every t("…") key exists ----
KEY = re.compile(r'\bt\(\s*"([\w.]+)"')
for f in sorted((WEB / "js").rglob("*.js")):
    for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("*", "//", "/*")) or "ns.key" in line:
            continue
        for m in KEY.finditer(line):
            k = m.group(1)
            if k not in fen:
                fail.append(f"{f.relative_to(ROOT)}:{i}: t(\"{k}\") missing from en.json")

# ---- no hardcoded demo data in UI code (payloads must come from fixtures) ----
DATA_PAT = [
    re.compile(r'https?://(?!localhost|127\.0\.0\.1|<)[a-zA-Z0-9.-]+'),   # absolute URLs
    re.compile(r'"\+971[\s0-9X-]{6,}"'),                                   # phone literals
    re.compile(r'"[^"]*\.(xyz|top|click|info|support|award)\b[^"]*"'),      # demo domains
]
for f in sorted((WEB / "js").rglob("*.js")):
    for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("*", "//", "/*")) or "import.meta.url" in line:
            continue
        if "new URL(" in line or "url(" in line.lower():
            continue
        for pat in DATA_PAT:
            m = pat.search(line)
            if m:
                fail.append(f"{f.relative_to(ROOT)}:{i}: hardcoded demo data → {m.group(0)[:50]}"
                            f"  (move it into web/fixtures/)")

# ---- WS3 boundary: files the brief assigns to other lanes must not exist here ----
FORBIDDEN = ["backend/app/main.py", "backend/app/config.py", "Dockerfile", "Makefile",
             "backend/run.sh", ".env"]
for rel in FORBIDDEN:
    if (ROOT / rel).exists():
        fail.append(f"{rel}: owned by another lane / not in the WS3 file list — remove it")

seed = ROOT / "backend" / "seed" / "fixtures"
if seed.exists():
    extra = {f.name for f in seed.glob("*.json")} - {"feed.json", "reports.json", "status.json"}
    if extra:
        fail.append(f"backend/seed/fixtures: only feed/reports/status belong to WS3, found {sorted(extra)}")

# every prompt the AI uses must exist (brief §3 lists four + the template skeletons
# that make the fallback path data-driven instead of hardcoded Python strings)
ai_dir = ROOT / "backend" / "app" / "ai" / "prompts"
REQUIRED_PROMPTS = {
    "case_summary.txt", "vision_note.txt", "takedown.txt", "why_smells.txt",
    "fallback_case_skeleton_en.txt", "fallback_case_skeleton_ar.txt",
    "fallback_takedown_template_en.txt", "fallback_why_template_en.txt",
}
missing = {n for n in REQUIRED_PROMPTS if not (ai_dir / n).exists()}
if missing:
    fail.append(f"ai/prompts: missing {sorted(missing)}")

# ---- no raw hex outside tokens.css ----
HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
for f in sorted((WEB / "css").glob("*.css")):
    if f.name == "tokens.css":
        continue
    for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        for m in HEX.finditer(line):
            fail.append(f"{f.relative_to(ROOT)}:{i}: raw hex {m.group(0)} outside tokens.css")

# ---- logical CSS gate: no left/right physical props in our sheets ----
PHYS = re.compile(r"(?<![-\w])(margin|padding|border)-(left|right)\s*:|(?<![-\w])(left|right)\s*:")
for f in sorted((WEB / "css").glob("*.css")):
    for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith(("/*", "*")):
            continue
        if PHYS.search(line):
            fail.append(f"{f.relative_to(ROOT)}:{i}: physical left/right property → use logical")

if fail:
    print(f"✗ i18n/design gate: {len(fail)} issue(s)")
    print("\n".join(fail[:80]))
    sys.exit(1)
print(f"✓ i18n/design gate clean — {len(fen)} keys × 2 languages, no hardcoded text, no raw hex, logical CSS only")
