"""AI Analyst (evidence-grounded).

POST /api/report/{id}/analysis  → text/event-stream deltas + final event   (investigator)
POST /api/report/{id}/takedown  → {letter_en}                              (investigator)

Input is ALWAYS built server-side from the stored report + its finding (never the
request body): C1 fields, the final tag, domain authentication and the official
verification evidence. The AI never writes verdict/score/reasons/tag.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from .. import security
from ..ai import client, fallback

router = APIRouter(prefix="/api/report", tags=["ai"])


def grounded_evidence(request: Request, report_id: int) -> dict:
    rt = request.app.state.runtime
    report = rt.repo.get_report(report_id)
    if not report:
        raise HTTPException(404, "report not found")
    evidence = dict(report.get("evidence") or {})
    finding = rt.get_finding(report["finding_id"]) or {}
    auth = finding.get("domain_auth") or {}
    gov = finding.get("gov_verification") or None
    evidence["tag"] = finding.get("tag") or evidence.get("tag")
    evidence["trust_reasons"] = finding.get("trust_reasons") or []
    evidence["domain_authentication"] = {k: auth.get(k) for k in ("status", "authenticated", "source_class", "reason")}
    if gov:
        evidence["official_verification"] = {
            "status": gov.get("status"),
            "coverage": gov.get("coverage"),
            "checked_sources": gov.get("checked_sources"),
            "unchecked_sources": gov.get("unchecked_sources"),
            "notes": gov.get("notes"),
            "evidence_id": gov.get("evidence_id"),
            "sources": [
                {k: item.get(k) for k in ("role", "comparison", "source_class", "organization", "source_url",
                                          "published_at", "retrieved_at", "excerpt", "detail", "synthetic")}
                for item in gov.get("evidence") or []
            ],
        }
    else:
        evidence["official_verification"] = {"status": "NOT_APPLICABLE",
                                             "notes": ["no government claim was verified for this finding"]}
    return evidence


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.post("/{report_id}/analysis")
async def analysis(report_id: int, request: Request):
    principal = security.require(request, "investigator")
    evidence = grounded_evidence(request, report_id)
    rt = request.app.state.runtime
    security.audit(request, principal, "ai.analysis", f"report:{report_id}")

    async def gen():
        yield ": daggers-ai\n\n"
        final: dict | None = None
        async for item in client.stream_case_summary(evidence, report_id=report_id):
            if "delta_text" in item:
                yield _sse("delta", item)
            else:
                final = item
        if final is None:
            final = fallback.case_summary(evidence)
        final["grounding"] = {
            "evidence_id": (evidence.get("official_verification") or {}).get("evidence_id"),
            "fields": sorted(k for k in evidence if k in client.ALLOWED_EVIDENCE_FIELDS),
        }
        rt.repo.save_report_ai(report_id, final)
        yield _sse("final", final)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@router.post("/{report_id}/takedown")
async def takedown(report_id: int, request: Request):
    principal = security.require(request, "investigator")
    evidence = grounded_evidence(request, report_id)
    security.audit(request, principal, "ai.takedown", f"report:{report_id}")
    return await client.takedown_letter(evidence)
