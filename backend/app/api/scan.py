from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from .. import security

router = APIRouter()


class ScanRequest(BaseModel):
    kind: Literal["url", "text"]
    input: str = Field(min_length=1, max_length=4000)
    lang: Literal["en", "ar"] = "en"


@router.post("/api/scan")
async def scan(payload: ScanRequest, request: Request, guard: int = Query(0, ge=0, le=1)):
    # Public endpoint for the Chrome extension: rate-limited per client, input never persisted.
    # The Checker uses POST /api/check, which stores every analysis for the Police Portal.
    rt = request.app.state.runtime
    ip = security.client_ip(request, rt.settings.trust_proxy_headers)
    if not rt.scan_limiter.hit(ip):
        raise HTTPException(status_code=429, detail="scan rate limit exceeded; try again in a minute")
    result = await run_in_threadpool(rt.scan, payload.kind, payload.input, payload.lang)
    host = ((result or {}).get("normalized") or {}).get("host") if isinstance(result, dict) else None
    if guard and payload.kind == "url" and host:
        # opt-in (?guard=1) so the scan contract stays exactly as it was; read-only Guard lookup; a browsing check is never added to the list (nothing is persisted)
        result = {**result, "guard": rt.guard.check(str(host))}
    return result
