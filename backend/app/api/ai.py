"""Daggers · AI endpoints (WS3 owns the explanation, never the verdict).

POST /api/report/{id}/analysis  → text/event-stream deltas + final event
POST /api/report/{id}/takedown  → {letter_en}

Input is ALWAYS canonical `Report.evidence` from WS1's repository. The request
body cannot inject user data, and AI never writes `verdict`, `score`, or
`reasons`. Final summaries/takedown letters are stored in `meta` as an audit
trail without changing the zero-PII report schema.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from ..ai import client

router = APIRouter(prefix="/api/report", tags=["ai"])


def _repo(request: Request):
    return request.app.state.runtime.repo


def _evidence(report_id: int, request: Request) -> dict:
    report = _repo(request).get_report(report_id)
    if not report:
        raise HTTPException(404, "report not found")
    return report.get("evidence") or {}


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n\n"


@router.post("/{report_id}/analysis")
async def analysis(report_id: int, request: Request):
    evidence = _evidence(report_id, request)

    async def gen():
        yield ": daggers-ai\n\n"
        final: dict | None = None
        async for item in client.stream_case_summary(evidence, report_id=report_id):
            if "delta_text" in item:
                yield _sse("delta", item)
            else:
                final = item
        if final is None:
            from ..ai import fallback
            final = fallback.case_summary(evidence)
        _repo(request).set_meta(f"ai:{report_id}", final)
        yield _sse("final", final)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/{report_id}/takedown")
async def takedown(report_id: int, request: Request):
    evidence = _evidence(report_id, request)
    result = await client.takedown_letter(evidence)
    _repo(request).set_meta(f"takedown:{report_id}", result)
    return result
