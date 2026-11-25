from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .. import security

router = APIRouter()


class ModeRequest(BaseModel):
    mode: Literal["live"]


@router.get("/api/status")
async def status(request: Request):
    return request.app.state.runtime.status()


@router.get("/api/mode")
async def get_mode(request: Request):
    return {"mode": request.app.state.runtime.mode}


@router.post("/api/mode")
async def set_mode(payload: ModeRequest, request: Request):
    principal = security.require(request, "admin")
    try:
        result = request.app.state.runtime.set_mode(payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    security.audit(request, principal, "runtime.mode", payload.mode)
    return result


@router.get("/api/healthz")
async def healthz(request: Request):
    runtime = request.app.state.runtime
    try:
        runtime.repo.get_meta("schema_version")
        db_ok = True
    except Exception:
        db_ok = False
    body = {"ok": db_ok, "mode": runtime.mode, "uptime_s": runtime.uptime_s(), "database": "ok" if db_ok else "error",
            "adapters": runtime.settings.adapter_status()}
    if not db_ok:
        raise HTTPException(status_code=503, detail=body)
    return body
