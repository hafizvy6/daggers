from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/api/examples")
async def examples(request: Request):
    """Canonical, non-PII query presets only.

    These come from the same curated `queries.yaml` the live sweep service uses.
    There are no sample findings, reported numbers, canned reports, or evidence.
    """
    from ..channels.sweep import load_queries

    queries = load_queries()
    sweep_web = [
        {"q": item["query"], "lang": item["lang"], "query_id": item.get("id")}
        for item in queries
        if item.get("channel") == "web"
    ]
    sweep_maps = [
        {"q": item["query"], "lang": item["lang"], "query_id": item.get("id")}
        for item in queries
        if item.get("channel") == "maps"
    ]
    settings = getattr(getattr(request.app.state, "runtime", None), "settings", None)
    sweep_arbitrary = bool(getattr(settings, "sweep_allow_arbitrary", False))
    return {"check": [], "numbers": [], "sweep_web": sweep_web, "sweep_maps": sweep_maps, "sweep_arbitrary": sweep_arbitrary}
