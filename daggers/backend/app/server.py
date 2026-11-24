"""Daggers · WS3 demo server — NOT part of my deliverable.

The brief says `main.py` / `config.py` / `Dockerfile` belong to Lane 1's shared
skeleton ("WS1 lands it first (hour 0–2)"). Until that lands, this file lets the
lane test its own screens end-to-end: it serves `web/` and mounts ONLY the two
WS3 routers (reports, ai). All other endpoints below are clearly-labelled
demo stand-ins that must be deleted the moment Lane 1's main.py exists.

CORS: reads the same `CORS_ORIGINS` env as Lane 1 (comma-separated origins).
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .store import store

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
SEED_FIXTURES = Path(__file__).resolve().parents[1] / "seed" / "fixtures"
APP_FIXTURES = WEB / "fixtures"

app = FastAPI(title="Daggers (WS3 demo server)", version="3.1.0")

_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- routers WS3 owns ----------------
from .api import ai as ai_router, reports as reports_router  # noqa: E402

app.include_router(reports_router.router)
app.include_router(ai_router.router)


# ================================================================
# DEMO STAND-INS — delete when Lane 1's app/main.py + api/* land.
# Shapes = the C-contracts in the brief, nothing more.
# ================================================================

@app.get("/share")
def share_landing():
    """PWA share_target target; the shell routes to #/check with the payload."""
    return FileResponse(WEB / "index.html")


@app.get("/api/feed", tags=["demo-standin"])
def demo_feed():
    return {"findings": store.list_findings(), "count": len(store.list_findings())}


@app.get("/api/finding/{finding_id}", tags=["demo-standin"])
def demo_finding(finding_id: int):
    return store.get_finding(finding_id) or {}


@app.get("/api/guard/stats", tags=["demo-standin"])
def demo_guard_stats():
    return store.guard_stats()


_OFFLINE_RULES = APP_FIXTURES / "offline_rules.json"


def _demo_number_scan(raw: str) -> dict:
    """Number check from the same rules file the UI uses offline (no invented data)."""
    rules = json.loads(_OFFLINE_RULES.read_text(encoding="utf-8"))
    digits = "".join(ch for ch in raw if ch.isdigit())
    if any(digits.startswith(pre) for pre in rules["premium_prefixes"]):
        return {"kind": "number", "input": raw, "verdict": "MALICIOUS",
                "score": rules["weights"].get("premium", 0.74),
                "reasons": ["premium-rate range (0900) — billed per minute",
                            "known pattern: missed-call bait — you call back and pay"],
                "scam_type": "premium-rate", "offline_capable": True}
    return {"kind": "number", "input": raw, "verdict": "UNKNOWN", "score": 0.0,
            "reasons": ["not in the known-pattern list"], "offline_capable": True}


@app.post("/api/scan", tags=["demo-standin"])
async def demo_scan(request: Request):
    body = await request.json()
    text = str(body.get("url") or body.get("text") or body.get("number") or body.get("input") or "")
    if body.get("number") or (body.get("input") and str(body["input"]).strip().replace("+", "").replace(" ", "").isdigit()):
        return _demo_number_scan(text)
    kind = "url" if "://" in text or "." in text else "text"
    for f in store.list_findings():
        if f["domain"] and f["domain"] in text:
            return {"kind": kind, "input": text, "verdict": f["verdict"], "score": f["score"],
                    "reasons": f.get("reasons", []), "reasons_ar": f.get("reasons_ar"),
                    "evidence_url": f.get("evidence_url"), "scam_type": f.get("scam_type"),
                    "offline_capable": True, "finding_id": f["id"]}
    return {"kind": kind, "input": text, "verdict": "UNKNOWN", "score": 0.0,
            "reasons": ["no signs found in the rules tier"], "offline_capable": True}


_SWEEPS = {}


@app.post("/api/sweep", tags=["demo-standin"])
async def demo_sweep_create(request: Request):
    """Contract: SweepRun is created with POST, then fetched by id with GET."""
    body = await request.json()
    channel = body.get("channel") or "web"
    name = "sweep_maps.json" if channel == "maps" else "sweep_web.json"
    run = json.loads((APP_FIXTURES / name).read_text(encoding="utf-8"))
    if body.get("query"):
        run["query"] = body["query"]
    if body.get("lang"):
        run["lang"] = body["lang"]
    _SWEEPS[run["id"]] = run
    return run


@app.get("/api/sweep/{run_id}", tags=["demo-standin"])
def demo_sweep_get(run_id: int, channel: str = "web"):
    if run_id in _SWEEPS:
        return _SWEEPS[run_id]
    name = "sweep_maps.json" if channel == "maps" else "sweep_web.json"
    return json.loads((APP_FIXTURES / name).read_text(encoding="utf-8"))


@app.get("/api/examples", tags=["demo-standin"])
def demo_examples():
    return store.examples()


@app.get("/api/status", tags=["demo-standin"])
def demo_status():
    return store.status()


@app.get("/api/mode", tags=["demo-standin"])
def demo_mode():
    return {"mode": "demo" if os.getenv("DEMO_MODE") == "1" else "live"}


@app.get("/api/stream", tags=["demo-standin"])
async def demo_stream():
    """SSE: one scripted finding after the beat delay, then heartbeats."""
    demo = json.loads((APP_FIXTURES / "stream_demo.json").read_text(encoding="utf-8"))

    async def gen():
        yield 'event: heartbeat\ndata: {"ok": true}\n\n'
        try:
            await asyncio.sleep(demo.get("beat_delay_ms", 14000) / 1000)
            finding = store.add_finding(demo["finding"])
            yield f'event: finding\ndata: {json.dumps(finding, ensure_ascii=False)}\n\n'
            store.create_report(finding_id=finding["id"], auto=True)
            while True:
                await asyncio.sleep(25)
                yield 'event: heartbeat\ndata: {"ok": true}\n\n'
        except asyncio.CancelledError:
            return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------- static web (same-origin: no CORS in local demo) ----------------
app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")
