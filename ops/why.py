#!/usr/bin/env python3
"""Why does the Checker give this verdict?  —  make why URL="https://www.adpolice.gov.ae/"

Runs the SAME analysis as the Checker (engine + live evidence + central verdict) on this machine and
prints the verdict, every reason and the status of every evidence source. Nothing is sent to the
Police Portal and nothing is stored.
"""
from __future__ import annotations

import sys

from backend.app import checker as checker_lib
from backend.app.config import Settings
from backend.app.main import Runtime


def main(argv: list[str]) -> int:
    if not argv:
        print('usage: make why URL="https://example.com/"')
        return 2
    rt = Runtime(Settings.from_env())
    rt.repo.initialize()
    if rt.trust_policy is None:
        print("TRUST POLICY NOT LOADED — the registry or lexicon could not be read (see server log). Nothing can be SAFE.")
        return 1
    value = " ".join(argv)
    classified = checker_lib.classify(value)
    result = rt.scan(classified.input_type, classified.value, "en", live=True, portal_evidence=False)
    auth = result.get("domain_auth") or {}
    print(f"\nINPUT   {classified.value}")
    print(f"VERDICT {result.get('tag')}    (engine: {result.get('verdict')}, score {result.get('score')})")
    print(f"DOMAIN  {auth.get('host')}: {auth.get('status')}  — {auth.get('reason')}")
    if auth.get("established"):
        print(f"        established-website check: {auth['established']}")
    print("\nWHY")
    for code, reason in zip(result.get("reason_codes") or [], result.get("trust_reasons") or []):
        print(f"  [{code}] {reason}")
    signals = [s for s in result.get("signals") or [] if float(s.get("weight") or 0) > 0]
    print("\nWARNING SIGNS" + ("" if signals else "   none"))
    for s in signals:
        print(f"  +{round(float(s['weight']) * 100)}  {s['name']}: {s.get('reason')}")
    print("\nEVIDENCE SOURCES (a source that says unavailable / timeout / LIST_MISSING could not be used)")
    for r in result.get("evidence") or []:
        print(f"  {r.get('id'):<20} {str(r.get('status')):<22} {r.get('summary') or ''}")
    print("\nWHAT TO DO")
    tips = []
    if auth.get("status") == "PENDING":
        tips.append('registry entry is pending → make setup-trust  (or: make approve-verified)')
    statuses = {r.get("id"): str(r.get("status")) for r in result.get("evidence") or []}
    if statuses.get("reputation") in ("LIST_MISSING", "LIST_STALE", "LIST_INVALID"):
        tips.append("ranking list not loaded → make reputation-update (needs internet)")
    if any(statuses.get(k) in ("unavailable", "timeout") for k in ("domain_age", "in_use_since", "page")):
        tips.append("live lookups failed → run: make doctor   (checks this machine's internet access)")
    for tip in tips or ["nothing to fix: the verdict follows from the evidence above"]:
        print("  - " + tip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
