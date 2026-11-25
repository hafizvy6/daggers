#!/usr/bin/env python3
"""Can this machine do what the Checker needs?  —  make doctor

Checks, from THIS machine, everything a SAFE verdict depends on and prints OK / FAIL with the reason:
registry approvals, the worldwide ranking list, and internet access to RDAP, certificate history,
the ranking list, and a real web page (through the same secure page retrieval the Checker uses).
"""
from __future__ import annotations

import os
import socket
import urllib.request

from backend.app.channels.official.registry import DEFAULT_REGISTRY_PATH, Registry
from backend.app.channels.reputation import Reputation
from backend.app.config import Settings
from backend.app.intel.probe import PageProbe

OK, FAIL, WARN = "OK  ", "FAIL", "WARN"


def line(state: str, what: str, detail: str = "") -> None:
    print(f"  [{state}] {what}" + (f" — {detail}" if detail else ""))


def reach(url: str, timeout: float = 8.0) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Daggers-doctor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https URLs
            resp.read(2048)
            return True, f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:140]}"


def main() -> int:
    s = Settings.from_env()
    problems = 0
    print("\n1. Official registry (government / verified organisations)")
    try:
        reg = Registry.load(s.official_registry_path or DEFAULT_REGISTRY_PATH)
        approved = [e.id for e in reg.entries if e.status == "approved"]
        pending = [e.id for e in reg.entries if e.status == "pending"]
        if approved:
            line(OK, f"{len(approved)} approved entries", ", ".join(approved[:8]) + ("…" if len(approved) > 8 else ""))
        else:
            problems += 1
            line(FAIL, "no approved entries — NO government site can be SAFE",
                 'run: make setup-trust  (or: make approve-verified)')
        if pending:
            line(WARN, f"{len(pending)} pending entries", ", ".join(pending[:8]) + ("…" if len(pending) > 8 else ""))
    except Exception as exc:  # noqa: BLE001
        problems += 1
        line(FAIL, "registry could not be loaded", str(exc)[:200])

    print("\n2. Worldwide ranking list (widely used sites)")
    rep = Reputation.load(s.reputation_list_path, top_n=s.reputation_top_n, max_age_days=s.reputation_max_age_days)
    st = rep.status()
    if st["loaded"] and not st["stale"]:
        line(OK, f"{st['domains']} domains loaded", f"list {st['list_id']} from {str(st['retrieved_at'])[:10]}")
    else:
        problems += 1
        line(FAIL, "ranking list not loaded" if not st["loaded"] else "ranking list is out of date",
             st.get("error") or "run: make reputation-update")

    print("\n3. Internet access from this machine (needed for live checks)")
    proxy = {k: v for k, v in os.environ.items() if k.lower() in ("https_proxy", "http_proxy", "no_proxy")}
    if proxy:
        line(WARN, "proxy settings in use", ", ".join(f"{k}={v[:60]}" for k, v in proxy.items()
                                                       if k.lower() != "no_proxy") or "no_proxy only")
    try:
        socket.getaddrinfo("data.iana.org", 443)
        line(OK, "DNS works")
    except OSError as exc:
        problems += 1
        line(FAIL, "DNS does not work", str(exc))
    for label, url, needed in (
        ("RDAP bootstrap (domain age)", "https://data.iana.org/rdap/dns.json", s.check_rdap_enabled),
        ("Certificate history (.ae ages)", f"{s.ct_api_url}?domain=example.com", s.check_ct_enabled),
        ("Ranking list download", "https://tranco-list.eu/top-1m-id", True),
        ("Public Suffix List", "https://publicsuffix.org/list/public_suffix_list.dat", True),
    ):
        if not needed:
            line(WARN, label, "switched off in .env")
            continue
        ok, why = reach(url)
        problems += 0 if ok else 1
        line(OK if ok else FAIL, label, why)
    if s.check_page_fetch_enabled:
        probe = PageProbe(total_timeout_s=10)
        r = probe.probe("https://www.adpolice.gov.ae/")
        good = r.status == "ok"
        problems += 0 if good else 1
        line(OK if good else FAIL, "Secure page retrieval (www.adpolice.gov.ae)",
             f"{r.status} {r.error_code or ''} {r.reason}".strip())
    else:
        line(WARN, "Secure page retrieval", "switched off in .env (CHECK_PAGE_FETCH_ENABLED=0)")

    print("\nRESULT: " + ("everything the Checker needs is available" if not problems else
                          f"{problems} problem(s) above — each FAIL line says what to do"))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
