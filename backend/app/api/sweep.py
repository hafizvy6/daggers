"""Sweep API (mounted by the optional-router loader).

POST /api/sweep        run one sweep (default query, or opted-in arbitrary query)
GET  /api/sweep/{id}   fetch a stored run

Routes are thin; logic lives in ``backend.app.channels.sweep``.
"""
from __future__ import annotations

import threading
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ..channels.maps import MapsChannel, default_maps_providers
from ..channels.scoring import ShieldScorer
from ..channels.search import SearchChannel, default_providers
from ..channels.sweep import RateLimiter, SweepError, SweepService
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
            runtime = getattr(state, "runtime", None)
            settings = getattr(runtime, "settings", None)
            scorer = ShieldScorer(
                catalog=getattr(runtime, "catalog", None),
                thresholds=getattr(settings, "thresholds", None),
            )
            # Settings are authoritative; no ambient OS env can silently enable
            # an external adapter or change its keys.
            search_env = {
                "SEARCH_LIVE_ENABLED": "1" if getattr(settings, "search_live_enabled", False) else "0",
                "SERPER_API_KEY": getattr(settings, "serper_api_key", "") or "",
            }
            maps_env = {
                "MAPS_LIVE_ENABLED": "1" if getattr(settings, "maps_live_enabled", False) else "0",
                "GOOGLE_PLACES_API_KEY": getattr(settings, "google_places_api_key", "") or "",
            }
            service = SweepService(
                search_channel=SearchChannel(scorer, providers=default_providers(search_env)),
                maps_channel=MapsChannel(scorer, providers=default_maps_providers(maps_env)),
                store=make_store(getattr(runtime, "repo", None)),
                allow_arbitrary=getattr(settings, "sweep_allow_arbitrary", False),
                limiter=RateLimiter(
                    per_minute=getattr(settings, "sweep_rate_per_min", 6),
                    max_concurrent=getattr(settings, "sweep_max_concurrent", 2),
                ),
                publish=getattr(runtime, "publish", None),
            )
            state.ws2_sweep = service
    return service


@router.post("/api/sweep")
async def create_sweep(payload: SweepRequest, request: Request):
    service = get_service(request)
    client = request.client.host if request.client else "unknown"
    try:
        return await run_in_threadpool(
            service.run, channel=payload.channel, lang=payload.lang,
            query_id=payload.query_id, query=payload.query, client=client,
        )
    except SweepError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@router.get("/api/sweep/{run_id}")
async def get_sweep(run_id: int, request: Request):
    result = get_service(request).get(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="sweep run not found")
    return result
