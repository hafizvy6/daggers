"""Daggers · reports API (portal routes over the shared SQLite repository).

GET  /api/reports                 list (evidence embedded)
GET  /api/reports/{id}            one
POST /api/reports                 410 — manual filing removed; actionable findings auto-queue
POST /api/reports/{id}/advance    QUEUED → SUBMITTED → SEEN
GET  /api/reports/{id}/export     evidence pack (JSON download)

All report data comes from `request.app.state.runtime.repo`, so SQL, canonical
shapes, and zero-PII validation live in `db/repo.py`.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/reports", tags=["reports"])
ORDER = ["QUEUED", "SUBMITTED", "SEEN"]


class AdvanceIn(BaseModel):
    status: str


def _runtime(request: Request):
    return request.app.state.runtime


def _repo(request: Request):
    return _runtime(request).repo



def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@router.get("")
def list_reports(request: Request):
    return {"reports": _repo(request).list_reports()}


@router.get("/{report_id}")
def get_report(report_id: int, request: Request):
    report = _repo(request).get_report(report_id)
    if not report:
        raise HTTPException(404, "report not found")
    return report


@router.post("", status_code=410)
def manual_report_removed():
    raise HTTPException(410, "manual report filing removed; actionable findings are queued automatically")


@router.post("/{report_id}/advance")
def advance(report_id: int, body: AdvanceIn, request: Request):
    if body.status not in ORDER:
        raise HTTPException(422, f"status must be one of {ORDER}")
    filed_at = _utc_now() if body.status == "SUBMITTED" else None
    report = _repo(request).set_report_status(report_id, body.status, filed_at=filed_at)
    if not report:
        raise HTTPException(404, "report not found")
    return report


@router.get("/{report_id}/export")
def export(report_id: int, request: Request):
    report = _repo(request).get_report(report_id)
    if not report:
        raise HTTPException(404, "report not found")
    return JSONResponse(
        report,
        headers={"Content-Disposition": f'attachment; filename="daggers-report-{report_id}.json"'},
    )
