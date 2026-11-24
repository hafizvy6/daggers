"""Daggers · reports API (WS3 owns the portal data path).

GET  /api/reports                 list (evidence embedded)
GET  /api/reports/{id}            one
POST /api/reports                 file a report  {finding_id}
POST /api/reports/{id}/advance    QUEUED → SUBMITTED → SEEN
GET  /api/reports/{id}/export     evidence pack (JSON download)

Schema forbids user fields — enforced in builder, restated here.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..store import store

router = APIRouter(prefix="/api/reports", tags=["reports"])
ORDER = ["QUEUED", "SUBMITTED", "SEEN"]


class FileIn(BaseModel):
    finding_id: int | None = None
    domain: str | None = None


class AdvanceIn(BaseModel):
    status: str


@router.get("")
def list_reports():
    return {"reports": store.list_reports()}


@router.get("/{report_id}")
def get_report(report_id: int):
    r = store.get_report(report_id)
    if not r:
        raise HTTPException(404, "report not found")
    return r


@router.post("", status_code=201)
def file_report(body: FileIn):
    finding = store.get_finding(body.finding_id) if body.finding_id is not None else None
    if not finding:
        raise HTTPException(404, "finding not found")
    existing = next((r for r in store.list_reports() if r.get("finding_id") == finding["id"]), None)
    if existing:
        return existing
    return store.create_report(finding_id=finding["id"], auto=False, channel="web")


@router.post("/{report_id}/advance")
def advance(report_id: int, body: AdvanceIn):
    if body.status not in ORDER:
        raise HTTPException(422, f"status must be one of {ORDER}")
    r = store.advance_report(report_id, body.status)
    if not r:
        raise HTTPException(404, "report not found")
    return r


@router.get("/{report_id}/export")
def export(report_id: int):
    r = store.get_report(report_id)
    if not r:
        raise HTTPException(404, "report not found")
    return JSONResponse(
        r,
        headers={"Content-Disposition": f'attachment; filename="daggers-report-{report_id}.json"'},
    )
