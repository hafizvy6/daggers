"""Sweep API (Search + Maps).

POST /api/sweep            investigator  start a sweep → 202 {id, status:"running", ...}
                                         (?wait=true runs inline and returns the finished run)
GET  /api/sweep            viewer        recent runs (status, counts)
GET  /api/sweep/{id}       viewer        one run with results (poll until status != running)

No synthetic data is ever used: without a configured live provider a sweep
fails honestly with "no provider configured". FAKE/MISLEADING live results are persisted
as findings (domain + evidence only).
"""
from __future__ import annotations

import threading
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import security
from ..channels.maps import MapsChannel, default_maps_providers
from ..channels.scoring import ShieldScorer
from ..channels.search import SearchChannel, default_providers
from ..channels.sweep import SweepError, SweepService
from ..channels.sweep_store import make_store

router = APIRouter()
_lock = threading.Lock()


class SweepRequest(BaseModel):
    channel: Literal["web", "maps"] = "web"
    lang: Literal["en", "ar"] = "en"
    query_id: str | None = Field(default=None, max_length=64)
    query: str | None = Field(default=None, max_length=200)


def get_service(request: Request) -> SweepService:
    state = request.app.state
    with _lock:
        service = getattr(state, "ws2_sweep", None)
        if service is None:
            runtime = state.runtime
            scorer = runtime.trust_policy or ShieldScorer(catalog=runtime.catalog,
                                                          thresholds=runtime.settings.thresholds)
            # Live providers only. Unconfigured → an honest failed run, never sample data.
            service = SweepService(
                search_channel=SearchChannel(scorer, providers=default_providers()),
                maps_channel=MapsChannel(scorer, providers=default_maps_providers()),
                store=make_store(runtime.repo),
                publish=runtime.publish,
                finding_sink=runtime.record_sweep_finding,
            )
            state.ws2_sweep = service
    return service


@router.post("/api/sweep")
async def create_sweep(payload: SweepRequest, request: Request, wait: bool = Query(False)):
    principal = security.require(request, "investigator")
    service = get_service(request)
    client = security.client_ip(request, request.app.state.runtime.settings.trust_proxy_headers)
    try:
        run = await run_in_threadpool(
            service.start, channel=payload.channel, lang=payload.lang, query_id=payload.query_id,
            query=payload.query, client=client, background=not wait,
        )
    except SweepError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    security.audit(request, principal, "sweep.start", f"sweep:{run['id']}",
                   detail={"channel": payload.channel, "query_id": run.get("query_id")})
    return JSONResponse(run, status_code=200 if wait else 202)


@router.get("/api/sweep")
async def list_sweeps(request: Request, limit: int = Query(50, ge=1, le=200)):
    security.require(request, "viewer")
    return {"runs": get_service(request).list_runs(limit)}


@router.get("/api/sweep/{run_id}")
async def get_sweep(run_id: int, request: Request):
    security.require(request, "viewer")
    result = get_service(request).get(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="sweep run not found")
    return result
