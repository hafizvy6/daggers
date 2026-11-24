from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

router = APIRouter()


def runtime(request: Request):
    return request.app.state.runtime


@router.get("/api/feed")
async def feed(request: Request, limit: int = Query(50, ge=1, le=200)):
    return runtime(request).get_findings(limit)


@router.get("/api/finding/{finding_id}")
async def finding(finding_id: int, request: Request):
    result = runtime(request).get_finding(finding_id)
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
