from __future__ import annotations

import copy
import re
from typing import Any

from ..core.verdicts import MALICIOUS

FINDING_KEYS = frozenset(
    {
        "id",
        "domain",
        "verdict",
        "score",
        "reasons",
        "cert_issued",
        "first_seen",
        "source",
        "clone",
        "evidence_url",
        "gallery_match",
        "is_case_file",
    }
)
REPORT_KEYS = frozenset(
    {"id", "finding_id", "evidence", "status", "auto", "filed_at", "blocked_hits"}
)
REPORT_STATUSES = frozenset({"QUEUED", "SUBMITTED", "SEEN"})

FORBIDDEN_TOKENS = (
    "user",
    "name",
    "phone",
    "email",
    "message",
    "msisdn",
    "imei",
    "contact",
    "address",
    "location",
    "device",
    "sender",
    "recipient",
    "body",
    "input",
    "cookie",
    "password",
    "secret",
    "credential",
    "latitude",
    "longitude",
    "coordinate",
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?:\+\d{9,}|\b\d{10,}\b)")


class PIIViolation(ValueError):
    """Raised when a report/evidence bundle contains a user-data field or value."""


def _walk(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lower = str(key).lower()
            if any(token in lower for token in FORBIDDEN_TOKENS):
                raise PIIViolation(f"forbidden key at {path}.{key}")
            _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if EMAIL_RE.search(value) or PHONE_RE.search(value):
            raise PIIViolation(f"forbidden contact-like value at {path}")
    elif isinstance(value, tuple):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]")


def validate_zero_pii(payload: dict) -> None:
    _walk(payload)


def build_evidence(finding: dict) -> dict:
    """Keep only artifacts of the fake site; never raw user input, messages, or contact data."""
    missing = FINDING_KEYS - set(finding)
    if missing:
        raise ValueError(f"Finding is missing contract keys: {sorted(missing)}")
    # Known integration fields on a stored finding (tag, verification detail, timestamps,
    # a Checker submission) are dropped — never copied into a report. Anything else is refused.
    from ..db.repo import FINDING_DETAIL_KEYS

    extra = set(finding) - FINDING_KEYS - set(FINDING_DETAIL_KEYS) - {"duplicate"}
    if extra:
        raise ValueError(f"Finding has non-contract keys: {sorted(extra)}")
    evidence = copy.deepcopy({key: finding[key] for key in FINDING_KEYS})
    validate_zero_pii(evidence)
    return evidence


def build_report(
    finding: dict,
    *,
    report_id: int,
    status: str = "QUEUED",
    auto: bool = True,
    filed_at: str | None = None,
    blocked_hits: int = 0,
) -> dict:
    if status not in REPORT_STATUSES:
        raise ValueError(f"invalid report status: {status}")
    report = {
        "id": int(report_id),
        "finding_id": int(finding["id"]),
        "evidence": build_evidence(finding),
        "status": status,
        "auto": bool(auto),
        "filed_at": filed_at,
        "blocked_hits": int(blocked_hits),
    }
    validate_zero_pii(report)
    return report


def autofile_eligible(finding: dict, clone_min: float = 90.0) -> bool:
    return finding.get("verdict") == MALICIOUS and float(finding.get("clone") or 0) >= clone_min
