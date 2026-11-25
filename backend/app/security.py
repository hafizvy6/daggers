"""Police Portal security: authentication, roles, CSRF, sessions, audit, rate limits.

* Passwords: scrypt (stdlib ``hashlib.scrypt``), per-user random salt, constant-time compare.
* Sessions: random 256-bit token in an HttpOnly, SameSite=Strict cookie
  (Secure in production). Only the SHA-256 of the token is stored server-side.
* CSRF: every state-changing request from a session must carry ``X-CSRF-Token``
  equal to the per-session token returned by ``GET /api/auth/me``.
* Roles (least privilege):  viewer < investigator < admin.
    viewer       read reports, findings, investigations, sweeps, Guard status
    investigator viewer + investigate URLs, run sweeps, file/advance reports, AI Analyst
    admin        investigator + users, audit log, runtime mode
* Every authentication event and every privileged action is written to audit_log.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

ROLES = ("viewer", "investigator", "admin")
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}
SESSION_COOKIE = "daggers_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MIN_PASSWORD_LEN = 12
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


# ------------------------------------------------------------------ passwords


def hash_password(password: str) -> str:
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            (password or "").encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=int(n), r=_SCRYPT["r"], p=_SCRYPT["p"], dklen=len(bytes.fromhex(digest_hex)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


_DUMMY_HASH = None


def dummy_verify() -> None:
    """Spend the same time on unknown usernames (no user-enumeration timing signal)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    verify_password("not-the-password", _DUMMY_HASH)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def iso_in(hours: int) -> str:
    when = datetime.now(timezone.utc) + timedelta(hours=hours)
    return when.isoformat(timespec="seconds").replace("+00:00", "Z")


def is_expired(iso_value: str) -> bool:
    try:
        when = datetime.fromisoformat(str(iso_value).replace("Z", "+00:00"))
    except ValueError:
        return True
    return when <= datetime.now(timezone.utc)


# ------------------------------------------------------------------ principal


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    role: str
    csrf_token: str

    def has(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[role]

    def public(self) -> dict:
        out = {"username": self.username, "role": self.role}
        if self.user_id == LOCAL_USER_ID:
            out["local"] = True
        return out


LOCAL_USER_ID = 0
LOCAL_USERNAME = "local"
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def is_local_request(request: Request) -> bool:
    """A request from a browser on this same machine, not relayed by any proxy."""
    if any(h in request.headers for h in ("x-forwarded-for", "x-real-ip", "forwarded")):
        return False
    return bool(request.client) and request.client.host in _LOOPBACK


def client_ip(request: Request, trust_proxy: bool = False) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def current_principal(request: Request) -> Principal | None:
    runtime = request.app.state.runtime
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 200:
        return _local_principal(request)
    row = runtime.repo.session_user(token_hash(token))
    if not row or not row.get("active") or is_expired(row.get("expires_at", "")):
        return _local_principal(request)
    return Principal(int(row["id"]), str(row["username"]), str(row["role"]), str(row["csrf_token"]))


def _local_principal(request: Request) -> Principal | None:
    """LOCAL_OPEN_ACCESS (development only, never in production): a browser on this machine is
    treated as a local admin without signing in. CSRF still applies: the token is per process
    and only readable same-origin via /api/auth/me, so other websites cannot act through it."""
    runtime = request.app.state.runtime
    if not runtime.settings.local_open_access or runtime.settings.is_production or not is_local_request(request):
        return None
    return Principal(LOCAL_USER_ID, LOCAL_USERNAME, "admin", runtime.local_csrf_token)


def require(request: Request, role: str = "viewer") -> Principal:
    """Authorize a request. Raises 401 (no session), 403 (role or CSRF)."""
    principal = current_principal(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if not principal.has(role):
        audit(request, principal, "authz.denied", request.url.path, outcome="denied", detail={"needed": role})
        raise HTTPException(status_code=403, detail=f"{role} role required")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent, principal.csrf_token):
            audit(request, principal, "csrf.rejected", request.url.path, outcome="denied")
            raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
    return principal


def audit(request: Request, principal: Principal | None, action: str, target: str | None = None,
          *, outcome: str = "ok", detail: dict | None = None) -> None:
    runtime = request.app.state.runtime
    try:
        runtime.repo.audit(
            username=principal.username if principal else None,
            action=action, target=target, outcome=outcome,
            client_ip=client_ip(request, runtime.settings.trust_proxy_headers), detail=detail,
        )
    except Exception:  # auditing must never take the service down; log loudly instead
        import logging

        logging.getLogger("daggers.audit").exception("audit write failed for %s", action)


# ------------------------------------------------------------------ rate limits


class SlidingWindow:
    """In-process sliding-window limiter (per key). Bounded memory."""

    def __init__(self, limit: int, window_s: float, clock=time.monotonic) -> None:
        self.limit, self.window_s, self.clock = limit, window_s, clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window_s:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10000:
                for stale in list(self._hits)[:2000]:
                    self._hits.pop(stale, None)
            return True

    def count(self, key: str) -> int:
        now = self.clock()
        with self._lock:
            hits = self._hits.get(key) or deque()
            return sum(1 for t in hits if now - t <= self.window_s)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


# ------------------------------------------------------------------ headers


def security_headers(production: bool) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        # Inline style attributes are used by the UI kit; scripts are same-origin modules only.
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
        ),
    }
    if production:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers
