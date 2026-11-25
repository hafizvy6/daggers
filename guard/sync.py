#!/usr/bin/env python3
"""Daggers Guard → AdGuard Home sync (VPS sidecar, Path B). Standard library only.

Reads the live Guard list from the Daggers backend and applies it to an AdGuard Home instance
through its HTTP control API.

Modes
  rules       (alias: hosts) write `||domain^` rules (or `$dnsrewrite` to GUARD_VERDICT_IP) into a
              marked block of AdGuard Home's custom rules. Rules you wrote yourself are kept.
  filter-url  register <daggers>/api/guard/adguard-rules.txt as a filter list and ask AdGuard
              Home to refresh it (AdGuard Home then downloads it on its own schedule too).
  rewrites    one DNS rewrite per domain → GUARD_VERDICT_IP (branded verdict page on HTTP).
              Rewrites this script did not create are never touched.

Usage
  python guard/sync.py --once                       # dry run: prints what would change
  python guard/sync.py --once --apply               # apply once
  python guard/sync.py --apply --interval 60        # keep syncing every 60 s

Environment
  DAGGERS_API          Daggers backend origin          (default http://127.0.0.1:8000)
  ADGUARD_URL          AdGuard Home origin              (default http://127.0.0.1:3000)
  ADGUARD_USER / ADGUARD_PASSWORD   AdGuard Home login (never commit them)
  GUARD_SYNC_MODE      rules | hosts | filter-url | rewrites   (default rules)
  GUARD_VERDICT_IP     verdict server IP (needed for rewrites; optional for rules)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

BEGIN = "! daggers-guard begin (managed by guard/sync.py — edits inside are replaced)"
END = "! daggers-guard end"
FILTER_NAME = "Daggers Guard"


class SyncError(RuntimeError):
    pass


def _http(opener, method: str, url: str, *, body=None, headers=None, timeout=15.0):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json, text/plain", **({"Content-Type": "application/json"} if data else {}),
        **(headers or {})})
    try:
        with opener(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        raise SyncError(f"{method} {url.split('?')[0]} → HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SyncError(f"{method} {url.split('?')[0]} unreachable: {exc}") from None


class AdGuardSync:
    def __init__(self, daggers: str, adguard: str, user: str = "", password: str = "", *,
                 mode: str = "rules", verdict_ip: str = "", opener=None):
        self.daggers = daggers.rstrip("/")
        self.adguard = adguard.rstrip("/")
        self.mode = "rules" if mode == "hosts" else mode
        if self.mode not in ("rules", "filter-url", "rewrites"):
            raise SyncError(f"unknown mode {mode!r}")
        if self.mode == "rewrites" and not verdict_ip:
            raise SyncError("rewrites mode needs GUARD_VERDICT_IP")
        self.verdict_ip = verdict_ip
        self.opener = opener or urllib.request.urlopen
        self.auth = ({"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}
                     if user else {})

    # ---------------------------------------------------------------- inputs

    def guard_domains(self) -> list[str]:
        _, raw = _http(self.opener, "GET", f"{self.daggers}/api/guard/domains.txt")
        out = []
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip().lower()
            if line and not line.startswith(("#", "!")) and " " not in line:
                out.append(line)
        return sorted(set(out))

    def _ag(self, method: str, path: str, body=None):
        status, raw = _http(self.opener, method, f"{self.adguard}{path}", body=body, headers=self.auth)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", "replace")

    # ---------------------------------------------------------------- modes

    def rules_for(self, domains: list[str]) -> list[str]:
        if self.verdict_ip:
            return [f"||{d}^$dnsrewrite=NOERROR;A;{self.verdict_ip}" for d in domains]
        return [f"||{d}^" for d in domains]

    def plan(self) -> dict:
        domains = self.guard_domains()
        if self.mode == "rules":
            status = self._ag("GET", "/control/filtering/status") or {}
            current = list(status.get("user_rules") or [])
            own = _outside_block(current)
            desired = own + [BEGIN] + self.rules_for(domains) + [END]
            return {"mode": "rules", "domains": len(domains), "changed": desired != current, "rules": desired}
        if self.mode == "filter-url":
            status = self._ag("GET", "/control/filtering/status") or {}
            url = f"{self.daggers}/api/guard/adguard-rules.txt"
            present = any((f or {}).get("url") == url for f in status.get("filters") or [])
            return {"mode": "filter-url", "domains": len(domains), "url": url, "add": not present}
        current = self._ag("GET", "/control/rewrite/list") or []
        ours = {(r["domain"], r["answer"]) for r in current if r.get("answer") == self.verdict_ip}
        want = {(d, self.verdict_ip) for d in domains}
        return {"mode": "rewrites", "domains": len(domains),
                "add": sorted(want - ours), "remove": sorted(ours - want)}

    def apply(self, plan: dict) -> dict:
        if plan["mode"] == "rules":
            if plan["changed"]:
                self._ag("POST", "/control/filtering/set_rules", {"rules": plan["rules"]})
            return {"applied": plan["changed"], "domains": plan["domains"]}
        if plan["mode"] == "filter-url":
            if plan["add"]:
                self._ag("POST", "/control/filtering/add_url",
                         {"name": FILTER_NAME, "url": plan["url"], "whitelist": False})
            self._ag("POST", "/control/filtering/refresh", {"whitelist": False})
            return {"applied": True, "domains": plan["domains"], "added_filter": plan["add"]}
        for domain, answer in plan["remove"]:
            self._ag("POST", "/control/rewrite/delete", {"domain": domain, "answer": answer})
        for domain, answer in plan["add"]:
            self._ag("POST", "/control/rewrite/add", {"domain": domain, "answer": answer})
        return {"applied": True, "added": len(plan["add"]), "removed": len(plan["remove"])}


def _outside_block(lines: list[str]) -> list[str]:
    out, inside = [], False
    for line in lines:
        if line == BEGIN:
            inside = True
            continue
        if line == END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="change AdGuard Home (default: dry run)")
    ap.add_argument("--once", action="store_true", help="run one sync and exit")
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between syncs (loop mode)")
    ap.add_argument("--mode", default=os.environ.get("GUARD_SYNC_MODE", "rules"))
    args = ap.parse_args(argv)
    try:
        sync = AdGuardSync(os.environ.get("DAGGERS_API", "http://127.0.0.1:8000"),
                           os.environ.get("ADGUARD_URL", "http://127.0.0.1:3000"),
                           os.environ.get("ADGUARD_USER", ""), os.environ.get("ADGUARD_PASSWORD", ""),
                           mode=args.mode, verdict_ip=os.environ.get("GUARD_VERDICT_IP", ""))
    except SyncError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    while True:
        try:
            plan = sync.plan()
            summary = {k: v for k, v in plan.items() if k != "rules"}
            if args.apply:
                print(json.dumps({"plan": summary, "result": sync.apply(plan)}, default=str))
            else:
                print(json.dumps({"dry_run": True, "plan": summary}, default=str))
        except SyncError as exc:
            print(f"sync failed: {exc}", file=sys.stderr)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(max(10.0, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
