"""Police Portal authentication and administration.

POST /api/auth/login      {username, password}  → sets HttpOnly session cookie
POST /api/auth/logout                            → clears session (CSRF required)
GET  /api/auth/me                                → {user, csrf_token} or 401
GET  /api/admin/users                            → admin
POST /api/admin/users      {username, password, role}            → admin
POST /api/admin/users/{username}/active  {active: bool}          → admin
GET  /api/admin/audit?limit=200                                  → admin
"""
from __future__ import annotations

import re
import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import security

router = APIRouter()
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=security.MIN_PASSWORD_LEN, max_length=256)
    role: Literal["viewer", "investigator", "admin"] = "viewer"


class ActiveIn(BaseModel):
    active: bool


def _runtime(request: Request):
    return request.app.state.runtime


@router.post("/api/auth/login")
async def login(payload: LoginIn, request: Request):
    runtime = _runtime(request)
    ip = security.client_ip(request, runtime.settings.trust_proxy_headers)
    username = payload.username.strip().lower()
    keys = (f"ip:{ip}", f"user:{username}")
    if any(runtime.login_failures.count(k) >= runtime.settings.login_max_failures for k in keys):
        security.audit(request, None, "auth.login", username, outcome="locked")
        raise HTTPException(status_code=429, detail="too many failed sign-in attempts; try again later")
    user = runtime.repo.get_user(username)
    if user is None:
        security.dummy_verify()
    ok = bool(user) and bool(user["active"]) and security.verify_password(payload.password, user["password_hash"])
    if not ok:
        for k in keys:
            runtime.login_failures.hit(k)
        security.audit(request, None, "auth.login", username, outcome="failed")
        raise HTTPException(status_code=401, detail="invalid username or password")
    for k in keys:
        runtime.login_failures.reset(k)
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    runtime.repo.create_session(security.token_hash(token), int(user["id"]), csrf,
                                security.iso_in(runtime.settings.session_ttl_hours))
    runtime.repo.touch_login(int(user["id"]))
    principal = security.Principal(int(user["id"]), user["username"], user["role"], csrf)
    security.audit(request, principal, "auth.login", username)
    response = JSONResponse({"user": principal.public(), "csrf_token": csrf})
    response.set_cookie(
        security.SESSION_COOKIE, token, max_age=runtime.settings.session_ttl_hours * 3600,
        httponly=True, secure=runtime.settings.cookie_secure, samesite="strict", path="/",
    )
    return response


@router.post("/api/auth/logout")
async def logout(request: Request):
    principal = security.require(request, "viewer")
    token = request.cookies.get(security.SESSION_COOKIE, "")
    _runtime(request).repo.delete_session(security.token_hash(token))
    security.audit(request, principal, "auth.logout")
    response = JSONResponse({"ok": True})
    response.delete_cookie(security.SESSION_COOKIE, path="/")
    return response


@router.get("/api/auth/me")
async def me(request: Request):
    principal = security.current_principal(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="not signed in")
    return {"user": principal.public(), "csrf_token": principal.csrf_token}


@router.get("/api/admin/users")
async def list_users(request: Request):
    security.require(request, "admin")
    return {"users": _runtime(request).repo.list_users()}


@router.post("/api/admin/users", status_code=201)
async def create_user(payload: UserIn, request: Request):
    principal = security.require(request, "admin")
    username = payload.username.strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=422, detail="username: 3–40 chars, a-z 0-9 . _ -")
    repo = _runtime(request).repo
    if repo.get_user(username):
        raise HTTPException(status_code=409, detail="user already exists")
    user = repo.create_user(username, security.hash_password(payload.password), payload.role)
    security.audit(request, principal, "admin.user.create", username, detail={"role": payload.role})
    return user


@router.post("/api/admin/users/{username}/active")
async def set_active(username: str, payload: ActiveIn, request: Request):
    principal = security.require(request, "admin")
    if username == principal.username and not payload.active:
        raise HTTPException(status_code=422, detail="you cannot disable your own account")
    if not _runtime(request).repo.set_user_active(username, payload.active):
        raise HTTPException(status_code=404, detail="user not found")
    security.audit(request, principal, "admin.user.active", username, detail={"active": payload.active})
    return {"username": username, "active": payload.active}


@router.get("/api/admin/audit")
async def audit_log(request: Request, limit: int = Query(200, ge=1, le=1000)):
    security.require(request, "admin")
    return {"entries": _runtime(request).repo.list_audit(limit)}
