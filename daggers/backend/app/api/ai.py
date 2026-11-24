"""Daggers · AI endpoints (WS3 owns).

POST /api/report/{id}/analysis  → text/event-stream deltas + final event
POST /api/report/{id}/takedown  → {letter_en}

(plan has vision_note.txt / why_smells.txt prompts in the client; the UI for those
 is on the cut list — no route is exposed until the screens show it.)

Input is ALWAYS Report.evidence from the store (never the request body):
zero PII by design, and the portal can't accidentally leak user context.
"""
from __future__ import annotations

import json
from typing import Iterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from ..ai import client
from ..store import store

router = APIRouter(prefix="/api/report", tags=["ai"])


def _evidence(report_id: int) -> dict:
    report = store.get_report(report_id)
    if not report:
        raise HTTPException(404, "report not found")
    return report.get("evidence") or {}


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.post("/{report_id}/analysis")
async def analysis(report_id: int):
    evidence = _evidence(report_id)

    async def gen():
        # heartbeat comment keeps proxies from buffering the stream
        yield ": daggers-ai\n\n"
        final: dict | None = None
        async for item in client.stream_case_summary(evidence, report_id=report_id):
            if "delta_text" in item:
                yield _sse("delta", item)
            else:
                final = item
        if final is None:  # defensive: never end without a final event
            from ..ai import fallback
            final = fallback.case_summary(evidence)
        store.save_ai(report_id, final)
        yield _sse("final", final)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/{report_id}/takedown")
async def takedown(report_id: int):
    evidence = _evidence(report_id)
    return await client.takedown_letter(evidence)



