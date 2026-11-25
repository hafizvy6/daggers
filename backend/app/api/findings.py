"""Findings, evidence and Guard (WS1 contracts C1/C6), tagged by the central trust policy.

Public: the radar feed and non-restricted findings (scam domains found by the radar or
sweeps). Restricted: findings created by Police Portal investigations (viewer role).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

from .. import security

router = APIRouter()


def runtime(request: Request):
    return request.app.state.runtime


@router.get("/api/feed")
async def feed(request: Request, limit: int = Query(50, ge=1, le=200)):
    principal = security.current_principal(request)
    return runtime(request).get_findings(limit, include_restricted=principal is not None)


@router.get("/api/finding/{finding_id}")
async def finding(finding_id: int, request: Request):
    rt = runtime(request)
    result = rt.get_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if rt.finding_is_restricted(finding_id):
        security.require(request, "viewer")
    return result


@router.get("/api/evidence/{finding_id}.jpg")
async def evidence_jpg(finding_id: int, request: Request):
    return _evidence_response(finding_id, request)


@router.get("/api/evidence/{finding_id}")
async def evidence(finding_id: int, request: Request):
    return _evidence_response(finding_id, request)


def _evidence_response(finding_id: int, request: Request) -> FileResponse:
    rt = runtime(request)
    if rt.finding_is_restricted(finding_id):
        security.require(request, "viewer")
    path = rt.ensure_evidence(finding_id)
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="evidence not found")
    return FileResponse(path, media_type="image/jpeg", filename=f"{finding_id}.jpg",
                        headers={"Cache-Control": "public, max-age=60"})


@router.get("/api/guard/feed")
async def guard_feed(request: Request):
    rows = runtime(request).guard_rows()
    body = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows)
    return Response(content=body, media_type="application/x-ndjson")


@router.get("/api/guard/stats")
async def guard_stats(request: Request):
    rt = runtime(request)
    rt.maybe_reload_registry()
    return rt.guard_stats(str(request.base_url).rstrip("/"))
