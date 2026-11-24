from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/examples")
async def examples():
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
    return {"check": [], "numbers": [], "sweep_web": sweep_web, "sweep_maps": sweep_maps}
