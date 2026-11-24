"""Daggers · WS3 demo store — DB-shaped, seeded from seed/fixtures.

Contract with WS1: when the real repo lands, `db/repo.py` replaces this module
(the API files import `store` and nothing else, so the swap is one file).
Everything here is the C1–C4 schema; no user fields exist in any record.
"""
from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path
from typing import Any

# Shared seed (only feed/reports/status — the three the brief assigns WS3) …
FIXTURES = Path(__file__).resolve().parents[1] / "seed" / "fixtures"
# … and the canonical demo assets the PWA also uses (single source of truth).
APP_FIXTURES = Path(__file__).resolve().parents[2] / "web" / "fixtures"
_LOCK = threading.Lock()


def _load(name: str) -> dict[str, Any]:
    path = (FIXTURES / name) if (FIXTURES / name).exists() else (APP_FIXTURES / name)
    return json.loads(path.read_text(encoding="utf-8"))


def _freshen(obj: dict[str, Any]) -> dict[str, Any]:
    """Re-anchor authored timestamps to 'minutes ago' (see fixtures README)."""
    now = time.time()
    for age_key, iso_key in (("age_min", "first_seen"), ("cert_age_min", "cert_issued"), ("filed_age_min", "filed_at")):
        if isinstance(obj.get(age_key), (int, float)) and obj.get(iso_key):
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - obj[age_key] * 60))
            obj[iso_key] = ts
    return obj


class Store:
    def __init__(self) -> None:
        self._findings: dict[int, dict] = {}
        self._reports: dict[int, dict] = {}
        self._seq_finding = 100
        self._seq_report = 100
        self.reload()

    # ---------------- seeding ----------------
    def reload(self) -> None:
        with _LOCK:
            feed = _load("feed.json")["findings"]
            for f in feed:
                f["evidence_url"] = f"/evidence/{f['id']}.jpg"
                self._findings[f["id"]] = copy.deepcopy(f)
                self._seq_finding = max(self._seq_finding, f["id"])
            reps = _load("reports.json")["reports"]
            for r in reps:
                r["evidence"] = copy.deepcopy(self._findings.get(r["finding_id"], r.get("evidence")))
                _freshen(r)
                _freshen(r["evidence"])
                self._reports[r["id"]] = r
                self._seq_report = max(self._seq_report, r["id"])
            self._stats = _load("guard_stats.json")
            self._status = _load("status.json")

    # ---------------- findings ----------------
    def list_findings(self) -> list[dict]:
        return sorted((copy.deepcopy(f) for f in self._findings.values()), key=lambda f: f["id"], reverse=True)

    def get_finding(self, fid: int) -> dict | None:
        f = self._findings.get(int(fid))
        return copy.deepcopy(f) if f else None

    def add_finding(self, finding: dict) -> dict:
        with _LOCK:
            self._seq_finding += 1
            finding["id"] = finding.get("id") or self._seq_finding
            finding["evidence_url"] = finding.get("evidence_url") or f"/evidence/{finding['id']}.jpg"
            _freshen(finding)
            self._findings[finding["id"]] = finding
            return copy.deepcopy(finding)

    # ---------------- reports ----------------
    def list_reports(self) -> list[dict]:
        return sorted((copy.deepcopy(r) for r in self._reports.values()), key=lambda r: r["id"], reverse=True)

    def get_report(self, rid: int) -> dict | None:
        r = self._reports.get(int(rid))
        return copy.deepcopy(r) if r else None

    def create_report(self, *, finding_id: int, auto: bool, channel: str = "web") -> dict:
        with _LOCK:
            self._seq_report += 1
            finding = self._findings.get(finding_id)
            report = {
                "id": self._seq_report,
                "finding_id": finding_id,
                "domain": finding["domain"] if finding else None,
                "status": "QUEUED",
                "auto": auto,
                "filed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "blocked_hits": 0,
                "channel": channel,
                "evidence": copy.deepcopy(finding),
            }
            self._reports[report["id"]] = report
            return copy.deepcopy(report)

    def advance_report(self, rid: int, status: str) -> dict | None:
        with _LOCK:
            r = self._reports.get(int(rid))
            if not r:
                return None
            r["status"] = status
            return copy.deepcopy(r)

    def save_ai(self, rid: int, payload: dict) -> None:
        with _LOCK:
            r = self._reports.get(int(rid))
            if r is not None:
                r["ai"] = {"summary_en": payload.get("summary_en"), "summary_ar": payload.get("summary_ar"),
                           "provider": payload.get("provider"), "fallback": payload.get("fallback", False),
                           "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # ---------------- misc ----------------
    def guard_stats(self) -> dict:
        return {**self._stats, "feed_size": sum(1 for f in self._findings.values() if f["verdict"] == "MALICIOUS")}

    def examples(self) -> dict:
        return _load("examples.json")

    def status(self) -> dict:
        return {**self._status, "counts": {**self._status.get("counts", {}),
                "findings": len(self._findings), "reports": len(self._reports)}}


store = Store()
