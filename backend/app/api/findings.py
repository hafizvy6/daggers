from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

router = APIRouter()


def runtime(request: Request):
    return request.app.state.runtime


@router.get("/api/feed")
async def feed(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    min_score: float = Query(0.35, ge=0.0, le=1.0),
    include_unknown: bool = Query(False),
    include_suppressed: bool = Query(False),
):
    return runtime(request).get_findings(
        limit,
        min_score=min_score,
        include_unknown=include_unknown,
        include_suppressed=include_suppressed,
    )


@router.get("/api/finding/{finding_id}")
async def finding(finding_id: int, request: Request):
    result = runtime(request).get_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return result


@router.get("/api/finding/{finding_id}/label")
async def get_label(finding_id: int, request: Request):
    if runtime(request).get_finding(finding_id) is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return runtime(request).get_finding_label(finding_id) or {"label": None}


@router.post("/api/finding/{finding_id}/label")
async def set_label(finding_id: int, request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="JSON body required") from None
    label = str(body.get("label", "")).strip().lower() if isinstance(body, dict) else ""
    if label not in {"official", "scam", "unrelated", "parked"}:
        raise HTTPException(status_code=422, detail="label must be official|scam|unrelated|parked")
    result = runtime(request).set_finding_label(finding_id, label)
    if result is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return result


@router.get("/api/evidence/{finding_id}.jpg")
async def evidence_jpg(finding_id: int, request: Request):
    return _evidence_response(finding_id, request)


@router.get("/api/evidence/{finding_id}")
async def evidence(finding_id: int, request: Request):
    return _evidence_response(finding_id, request)


def _evidence_response(finding_id: int, request: Request) -> FileResponse:
    path = runtime(request).ensure_evidence(finding_id)
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="evidence not found")
    return FileResponse(
        path,
        media_type="image/jpeg",
        filename=f"{finding_id}.jpg",
        headers={"Cache-Control": "public, max-age=60"},
    )


@router.get("/api/guard/feed")
async def guard_feed(request: Request):
    rows = runtime(request).guard_rows()
    body = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    )
    return Response(content=body, media_type="application/x-ndjson")


@router.get("/api/guard/stats")
async def guard_stats(request: Request):
    return runtime(request).guard_stats()
