from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class ModeRequest(BaseModel):
    mode: Literal["live", "demo"]


@router.get("/api/status")
async def status(request: Request):
    return request.app.state.runtime.status()


@router.get("/api/mode")
async def get_mode(request: Request):
    return {"mode": request.app.state.runtime.mode}


@router.post("/api/mode")
async def set_mode(payload: ModeRequest, request: Request):
    return request.app.state.runtime.set_mode(payload.mode)


@router.get("/api/healthz")
async def healthz(request: Request):
    runtime = request.app.state.runtime
    return {"ok": True, "mode": runtime.mode, "uptime_s": runtime.uptime_s()}
