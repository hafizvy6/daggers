"""Police Portal investigations: submit a URL → scan → verify → PERSIST → display.

POST /api/investigations   {url, page_text?}   investigator   → stored finding (tagged)
GET  /api/investigations?limit=100              viewer         → recent investigation findings
"""
from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from .. import security

router = APIRouter()


class InvestigationIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    page_text: str | None = Field(default=None, max_length=8000)


@router.post("/api/investigations", status_code=201)
async def create(payload: InvestigationIn, request: Request):
    principal = security.require(request, "investigator")
    rt = request.app.state.runtime
    finding = await run_in_threadpool(rt.investigate, payload.url, payload.page_text, principal.username)
    security.audit(request, principal, "investigation.create", f"finding:{finding['id']}",
                   detail={"domain": finding["domain"], "tag": finding.get("tag")})
    return finding


@router.get("/api/investigations")
async def list_investigations(request: Request, limit: int = Query(100, ge=1, le=500)):
    security.require(request, "viewer")
    rt = request.app.state.runtime
    return {"findings": [rt.tag(f) for f in rt.repo.findings_by_source("investigation", limit)]}
