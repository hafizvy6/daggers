"""System information for the portal and the PWA.

GET /api/readiness  admin  — configuration truth: env, registry approvals, users, trust policy
GET /api/registry   viewer — official-source registry summary (status, class, domains)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from .. import security

router = APIRouter()


@router.get("/api/readiness")
async def readiness(request: Request):
    security.require(request, "admin")
    return request.app.state.runtime.readiness()


@router.get("/api/registry")
async def registry(request: Request):
    security.require(request, "viewer")
    rt = request.app.state.runtime
    if rt.trust_policy is None:
        return {"available": False, "entries": []}
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    reg = rt.trust_policy.registry
    return {
        "available": True,
        "version": reg.version,
        "entries": [
            {"id": e.id, "organization": e.organization, "source_class": e.source_class,
             "jurisdiction": e.jurisdiction, "domains": list(e.domains), "status": e.status,
             "trusted": e.is_trusted(now), "reviewer": e.reviewer, "verified_at": e.verified_at,
             "max_age_days": e.max_age_days}
            for e in reg.entries
        ],
    }


@router.get("/share")
async def share_landing(request: Request):
    """PWA share_target landing: the shell routes /share?url=… to the Checker."""
    index = request.app.state.runtime.settings.web_dir / "index.html"
    if not index.exists():
        raise HTTPException(404, "web app not installed")
    return FileResponse(index, media_type="text/html")
