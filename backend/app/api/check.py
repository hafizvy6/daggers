"""Live Checker and the Police Portal findings index.

POST /api/check     public   {input, lang, request_id}  → stored finding (201 new, 200 same request)
GET  /api/portal/findings  viewer  ?q&tag&input_type&source&date_from&date_to&limit&offset

Every successful check is persisted as a finding (source "checker") and is visible
only inside the Police Portal. The response IS the stored finding, so the Checker
and the Portal always show the same verdict and evidence.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import security
from ..checker import CheckInputError
from ..main_errors import CheckFailed

router = APIRouter()

REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
TAGS = ("SAFE", "WARNING", "MISLEADING", "FAKE")


class CheckIn(BaseModel):
    input: str = Field(max_length=4000)
    lang: Literal["en", "ar"] = "en"
    request_id: str = Field(min_length=8, max_length=64)


@router.post("/api/check")
async def check(payload: CheckIn, request: Request):
    rt = request.app.state.runtime
    if not REQUEST_ID.match(payload.request_id):
        raise HTTPException(status_code=422, detail={"code": "bad_request_id", "message": "invalid request id"})
    ip = security.client_ip(request, rt.settings.trust_proxy_headers)
    if not rt.scan_limiter.hit(ip):
        raise HTTPException(status_code=429, detail={"code": "rate_limited",
                                                     "message": "too many checks; try again in a minute"})
    try:
        finding, created = await run_in_threadpool(rt.check, payload.input, payload.lang, payload.request_id, ip)
    except CheckInputError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message}) from exc
    except CheckFailed as exc:
        return JSONResponse(status_code=503, content={"detail": {"code": exc.code, "message": exc.message,
                                                                 "result": exc.result}})
    return JSONResponse(status_code=201 if created else 200, content={**finding, "duplicate": not created})


def _day(value: str | None, field: str, plus_one: bool = False) -> str | None:
    if not value:
        return None
    try:
        parsed = date.fromisoformat(value[:10])
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{field} must be YYYY-MM-DD") from None
    return (parsed + timedelta(days=1 if plus_one else 0)).isoformat()


@router.get("/api/portal/findings")
async def portal_findings(
    request: Request,
    q: str | None = Query(None, max_length=200),
    tag: Literal["SAFE", "WARNING", "MISLEADING", "FAKE"] | None = None,
    input_type: Literal["url", "text", "domain"] | None = None,
    source: Literal["checker", "investigation", "radar", "sweep", "crt", "feeds"] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=5000),
):
    security.require(request, "viewer")
    rt = request.app.state.runtime
    return await run_in_threadpool(
        lambda: rt.portal_findings(
            q=q, tag=tag, input_type=input_type, source=source,
            date_from=_day(date_from, "date_from"), date_to=_day(date_to, "date_to", plus_one=True),
            limit=limit, offset=offset,
        )
    )
