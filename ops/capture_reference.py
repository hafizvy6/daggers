#!/usr/bin/env python3
"""Capture real official-page reference screenshots for clone comparison.

This is an operator-run, read-only capture tool. It never commits or redistributes
the images; they stay under GALLERY_DIR on the machine that runs the renderer.

Examples:
  python ops/capture_reference.py adnoc.ae adcb.ae
  python ops/capture_reference.py --all-brands
  python ops/capture_reference.py adnoc.ae --force   # replace a bad cached capture
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.catalog import load_catalogs
from backend.app.config import Settings
from backend.app.vision.render import render_for_reference


async def main_async(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    settings = dataclasses.replace(settings, render_enabled=True)
    catalog = load_catalogs()

    domains = list(args.domains)
    if args.all_brands:
        domains.extend(str(brand["official_domain"]) for brand in catalog.brands)

    seen: set[str] = set()
    ok = 0
    for domain in domains:
        host = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        result = await render_for_reference(host, settings, force=args.force)
        if result.screenshot_path and Path(result.screenshot_path).exists():
            print(f"OK   {host} -> {result.screenshot_path}")
            ok += 1
        else:
            print(f"FAIL {host} -> {result.error or 'no capture'}")
    print(f"captured {ok}/{len(seen)} reference page(s)")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("domains", nargs="*", help="official domains or hosts, e.g. adnoc.ae")
    parser.add_argument("--all-brands", action="store_true", help="capture every catalogued official domain")
    parser.add_argument("--force", action="store_true", help="overwrite existing reference captures")
    args = parser.parse_args()
    if not args.domains and not args.all_brands:
        parser.error("pass one or more domains, or --all-brands")
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
