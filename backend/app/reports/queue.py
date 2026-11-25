from __future__ import annotations

import json
from datetime import datetime, timezone

from .builder import autofile_eligible, build_evidence, validate_zero_pii


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ReportQueue:
    """C4 lifecycle. Only a Finding contract object may become report evidence."""

    def __init__(self, repo, *, clone_min: float = 90.0) -> None:
        self.repo = repo
        self.clone_min = clone_min

    def maybe_auto_file(self, finding: dict, *, blocked_hits: int = 0) -> dict | None:
        if not autofile_eligible(finding, self.clone_min):
            return None
        evidence = build_evidence(finding)
        validate_zero_pii(evidence)
        return self.repo.insert_report(
            finding_id=int(finding["id"]),
            evidence=evidence,
            status="QUEUED",
            auto=True,
            filed_at=None,
            blocked_hits=blocked_hits,
        )

    def submit_queued(self, limit: int = 20) -> list[dict]:
        submitted: list[dict] = []
        for report in self.repo.list_reports(status="QUEUED", limit=limit):
            updated = self.repo.set_report_status(report["id"], "SUBMITTED", filed_at=utc_now())
            if updated:
                submitted.append(updated)
        return submitted

    def mark_seen(self, report_id: int) -> dict | None:
        return self.repo.set_report_status(report_id, "SEEN")

    def export(self, report_id: int) -> bytes:
        report = self.repo.get_report(report_id)
        if report is None:
            raise KeyError(f"report {report_id} not found")
        validate_zero_pii(report)
        return json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
