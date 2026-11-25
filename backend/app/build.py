"""Build fingerprint: a hash of the application's code and data files (rules, registry, lexicon,
catalogues, suffix list). Anything that can change a verdict changes the fingerprint, so results
stored by an older build are never reused (Checker store) — no manual version bump needed."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
PATTERNS = ("*.py", "*.yaml", "*.yml", "*.json", "*.dat")


@lru_cache(maxsize=1)
def fingerprint() -> str:
    digest = hashlib.sha256()
    for pattern in PATTERNS:
        for path in sorted(APP_DIR.rglob(pattern)):
            if "__pycache__" in path.parts:
                continue
            digest.update(str(path.relative_to(APP_DIR)).encode())
            try:
                digest.update(path.read_bytes())
            except OSError:
                continue
    return "build_" + digest.hexdigest()[:16]
