#!/usr/bin/env python3
"""Push the Daggers Guard blocklist to a NextDNS profile denylist.

    python guard/sync_nextdns.py --api http://localhost:8000            # dry run (default)
    NEXTDNS_API_KEY=... NEXTDNS_PROFILE=abc123 \\
        python guard/sync_nextdns.py --api http://localhost:8000 --apply

* Reads GET /api/guard/blocklist.txt?format=domains (confirmed-malicious only).
* Adds missing domains to the profile denylist; never removes entries it did not add
  unless --prune is given (entries it added are tracked in a local state file).
* The API key is read from the environment only. Never commit it.
* NOT validated against the live NextDNS API from the WS2 build environment.
  NextDNS does not give WS2 block-event counts; this script never reports any.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

NEXTDNS = "https://api.nextdns.io"
UA = "Daggers-Research/1.0"
DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def fetch_blocklist(api_base: str, timeout: float = 10) -> list[str]:
    url = api_base.rstrip("/") + "/api/guard/blocklist.txt?format=domains"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-supplied own server
        text = resp.read(2_000_000).decode("utf-8", errors="replace")
    domains = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return [d for d in domains if DOMAIN.match(d)]


def _nextdns(method: str, path: str, key: str, body: dict | None = None):
    req = urllib.request.Request(
        NEXTDNS + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-Api-Key": key, "Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed host
        raw = resp.read()
    return json.loads(raw) if raw else {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", default=os.environ.get("DAGGERS_API", "http://localhost:8000"))
    ap.add_argument("--apply", action="store_true", help="actually call NextDNS (default: dry run)")
    ap.add_argument("--prune", action="store_true", help="remove domains this script added earlier that are no longer listed")
    ap.add_argument("--state", default=str(Path(__file__).resolve().parents[1] / "backend" / "data" / "nextdns_state.json"))
    args = ap.parse_args(argv)

    wanted = fetch_blocklist(args.api)
    state_path = Path(args.state)
    added_before = set(json.loads(state_path.read_text())["added"]) if state_path.exists() else set()
    print(f"blocklist: {len(wanted)} confirmed-malicious domain(s)")
    if not args.apply:
        for d in wanted:
            print(f"  would deny {d}")
        print("dry run — nothing sent to NextDNS")
        return 0
    key, profile = os.environ.get("NEXTDNS_API_KEY"), os.environ.get("NEXTDNS_PROFILE")
    if not key or not profile or not re.fullmatch(r"[a-z0-9]{4,12}", profile):
        print("NEXTDNS_API_KEY and a valid NEXTDNS_PROFILE are required for --apply", file=sys.stderr)
        return 2
    try:
        current = {item["id"] for item in _nextdns("GET", f"/profiles/{profile}/denylist", key).get("data", [])}
        added = set(added_before)
        for d in wanted:
            if d not in current:
                _nextdns("POST", f"/profiles/{profile}/denylist", key, {"id": d, "active": True})
                added.add(d)
                print(f"  denied {d}")
        if args.prune:
            for d in sorted(added_before - set(wanted)):
                if d in current:
                    _nextdns("DELETE", f"/profiles/{profile}/denylist/{d}", key)
                    print(f"  removed {d}")
                added.discard(d)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"NextDNS sync failed: {type(exc).__name__}; nothing further changed", file=sys.stderr)
        return 1
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"added": sorted(added)}))
    print("sync complete (block events are not measured by this tool)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
