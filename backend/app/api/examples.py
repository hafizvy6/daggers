"""GET /api/examples — curated Sweep query presets. No sample findings, scans or reports."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/examples")
async def examples():
    """Curated Sweep query presets only (the same queries.yaml the sweep service uses).

    There are no sample findings, scans, reports or evidence: the Checker has no
    preset inputs, and nothing here is ever shown as a result.
    """
    from ..channels.sweep import load_queries

    queries = load_queries()
    pick = lambda channel: [  # noqa: E731
        {"q": item["query"], "lang": item["lang"], "query_id": item.get("id")}
        for item in queries if item.get("channel") == channel
    ]
    return {"check": [], "numbers": [], "sweep_web": pick("web"), "sweep_maps": pick("maps")}
