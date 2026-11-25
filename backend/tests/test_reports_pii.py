from __future__ import annotations

import copy
import json

import pytest

from backend.app.reports.builder import (
    FINDING_KEYS,
    PIIViolation,
    autofile_eligible,
    build_evidence,
    build_report,
    validate_zero_pii,
)
from backend.app.reports.queue import ReportQueue

FINDING = {
    "id": 42,
    "domain": "adcb-secure-login.xyz",
    "verdict": "MALICIOUS",
    "score": 0.93,
    "reasons": ["brand typo/name 'adcb' (distance 0) outside adcb.ae"],
    "cert_issued": "2026-11-24T07:58:00Z",
    "first_seen": "2026-11-24T08:01:00Z",
    "source": "crt.sh",
    "clone": 97,
    "evidence_url": "/evidence/42.jpg",
    "gallery_match": "adcb.ae/login",
    "is_case_file": False,
}


class FakeRepo:
    def __init__(self):
        self.reports: list[dict] = []

    def insert_report(self, **kwargs):
        report = build_report(
            FINDING,
            report_id=len(self.reports) + 7,
            status=kwargs["status"],
            auto=kwargs["auto"],
            filed_at=kwargs["filed_at"],
            blocked_hits=kwargs["blocked_hits"],
        )
        self.reports.append(report)
        return report

    def list_reports(self, status=None, limit=50):
        rows = self.reports if status is None else [row for row in self.reports if row["status"] == status]
        return rows[:limit]

    def set_report_status(self, report_id, status, filed_at=None):
        for row in self.reports:
            if row["id"] == report_id:
                row["status"] = status
                if filed_at:
                    row["filed_at"] = filed_at
                return copy.deepcopy(row)
        return None

    def get_report(self, report_id):
        return next((copy.deepcopy(row) for row in self.reports if row["id"] == report_id), None)


def test_evidence_contains_exact_finding_contract():
    evidence = build_evidence(FINDING)
    assert set(evidence) == FINDING_KEYS
    assert evidence["domain"] == "adcb-secure-login.xyz"
    assert evidence["clone"] == 97


def test_build_report_shape_and_zero_pii():
    report = build_report(FINDING, report_id=7, status="QUEUED")
    assert set(report) == {"id", "finding_id", "evidence", "status", "auto", "filed_at", "blocked_hits"}
    assert report["finding_id"] == 42
    validate_zero_pii(report)


def test_nested_user_key_is_rejected():
    payload = copy.deepcopy(FINDING)
    payload["context"] = {"user_name": "someone"}
    with pytest.raises(ValueError):
        build_evidence(payload)
    with pytest.raises(PIIViolation):
        validate_zero_pii({"evidence": {"reasons": [{"phone_number": "x"}]}})


def test_contact_like_values_are_rejected():
    bad_email = copy.deepcopy(FINDING)
    bad_email["reasons"] = ["contact victim@example.com"]
    with pytest.raises(PIIViolation):
        validate_zero_pii(bad_email)
    bad_phone = copy.deepcopy(FINDING)
    bad_phone["reasons"] = ["callback +971501234567"]
    with pytest.raises(PIIViolation):
        validate_zero_pii(bad_phone)


def test_autofile_rule_requires_malicious_and_clone_proof():
    assert autofile_eligible(FINDING) is True
    assert autofile_eligible({**FINDING, "clone": 0}) is False
    assert autofile_eligible({**FINDING, "verdict": "SUSPICIOUS"}) is False


def test_report_queue_autofiles_and_submits_without_pii():
    repo = FakeRepo()
    queue = ReportQueue(repo)
    report = queue.maybe_auto_file(FINDING, blocked_hits=12)
    assert report is not None
    assert report["status"] == "QUEUED"
    assert report["blocked_hits"] == 12
    submitted = queue.submit_queued()
    assert submitted[0]["status"] == "SUBMITTED"
    exported = json.loads(queue.export(report["id"]))
    validate_zero_pii(exported)
