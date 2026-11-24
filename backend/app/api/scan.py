from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

router = APIRouter()


class ScanRequest(BaseModel):
    kind: Literal["url", "text", "number"]
    input: str = Field(min_length=1, max_length=4000)
    lang: Literal["en", "ar"] = "en"


@router.post("/api/scan")
async def scan(payload: ScanRequest, request: Request):
    # The route is intentionally thin. The pure brain owns every verdict.
    return request.app.state.runtime.scan(payload.kind, payload.input, payload.lang)
