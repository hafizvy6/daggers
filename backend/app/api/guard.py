"""WS2 Guard API — adds ONLY two endpoints (WS1 keeps /api/guard/feed and /api/guard/stats).

GET /api/guard/blocklist.txt?format=hosts|domains
GET /api/guard/sync-status
"""
from __future__ import annotations

import os
import threading
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import PlainTextResponse

from ..channels.guard import DEFAULT_MAX_AGE_DAYS, GuardSync, render
from ..channels.official.registry import Registry

router = APIRouter()
_lock = threading.Lock()


def get_sync(request: Request) -> GuardSync:
    state = request.app.state
    with _lock:
        sync = getattr(state, "ws2_guard", None)
        if sync is None:
            runtime = state.runtime
            sync = GuardSync(
                registry=Registry.load(),
                official_domains=tuple(runtime.catalog.official_domains),
                source=runtime.guard_rows,  # WS1's existing Guard feed, in-process
                max_age_days=int(os.environ.get("GUARD_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS)),
            )
            state.ws2_guard = sync
    return sync


@router.get("/api/guard/blocklist.txt")
async def blocklist(request: Request, format: Literal["hosts", "domains"] = Query("hosts")):
    sync = get_sync(request)
    result = sync.sync()
    if result is None:
        return PlainTextResponse("# Daggers Guard: feed unavailable and no previous list\n", status_code=503)
    return PlainTextResponse(render(result, format), headers={"Cache-Control": "public, max-age=60"})


@router.get("/api/guard/sync-status")
async def sync_status(request: Request):
    sync = get_sync(request)
    sync.sync()
    return sync.status(getattr(request.app.state.runtime, "mode", None))
