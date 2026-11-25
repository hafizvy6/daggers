"""NextDNS live provider: push the Guard list to a NextDNS profile denylist.

API (https://nextdns.github.io/api/): header ``X-Api-Key``; ``POST /profiles/{id}/denylist`` with
``{"id": domain, "active": true}``; ``DELETE`` ``/profiles/{id}/denylist/{domain}``. Successful responses are
``{"data": …}``; errors are ``{"errors": […]}`` — some user errors arrive with HTTP 200, so the body is
checked. A denylist holds at most 5,000 entries. Rate limits are not documented: HTTP 429 stops the
run and honours ``Retry-After``.

Only entries the Guard itself added are ever removed (tracked in ``guard_pushed``); entries you add
by hand in the NextDNS dashboard are never touched.

Analytics: ``GET /profiles/{id}/analytics/reasons?from=-24h`` — the ``denylist`` reason counts queries
blocked by the denylist in the last 24 h (ALL denylist entries, including any you added yourself).
If the key/plan does not allow it, the number is reported as unavailable — never invented.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

import httpx

API = "https://api.nextdns.io"
MAX_ENTRIES = 5000


@dataclass
class PushResult:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rate_limited: bool = False
    retry_after_s: float | None = None
    skipped_over_limit: int = 0
    already_present: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"added": len(self.added), "removed": len(self.removed), "errors": self.errors[:10],
                "rate_limited": self.rate_limited, "retry_after_s": self.retry_after_s,
                "skipped_over_limit": self.skipped_over_limit, "already_present": len(self.already_present)}


def _default_http(method: str, url: str, *, headers: dict, json: dict | None, timeout: float):
    with httpx.Client(timeout=timeout) as client:
        return client.request(method, url, headers=headers, json=json)


class NextDNSProvider:
    name = "nextdns"

    def __init__(self, profile: str, api_key: str, *, timeout_s: float = 8.0, max_ops: int = 300,
                 http: Callable | None = None, clock: Callable[[], float] = time.time) -> None:
        self.profile = (profile or "").strip()
        self.api_key = (api_key or "").strip()
        self.timeout_s = timeout_s
        self.max_ops = max_ops
        self.http = http or _default_http
        self.clock = clock
        self._analytics: tuple[float, int | None, str | None] | None = None
        self.foreign: set[str] = set()   # already on the denylist before us (added by hand): never ours

    @property
    def configured(self) -> bool:
        return bool(self.profile and self.api_key)

    def _call(self, method: str, path: str, body: dict | None = None):
        return self.http(method, f"{API}/profiles/{self.profile}{path}",
                         headers={"X-Api-Key": self.api_key, "Accept": "application/json"},
                         json=body, timeout=self.timeout_s)

    @staticmethod
    def _errors(resp) -> list[str]:
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            return []
        errs = payload.get("errors") if isinstance(payload, dict) else None
        return [str(e.get("code") or e.get("detail") or e) for e in errs] if errs else []

    def push(self, desired: set[str], pushed: set[str]) -> PushResult:
        """Make the profile denylist contain `desired` (for entries we manage). Diff-based, bounded."""
        out = PushResult()
        if not self.configured:
            out.errors.append("not configured")
            return out
        to_add = sorted(desired - pushed - self.foreign)
        to_remove = sorted(pushed - desired)
        room = MAX_ENTRIES - len(pushed & desired)
        if len(to_add) > room:
            out.skipped_over_limit = len(to_add) - room
            to_add = to_add[:max(0, room)]
        ops = 0
        for domain in to_remove:
            if ops >= self.max_ops:
                break
            ops += 1
            try:
                resp = self._call("delete", f"/denylist/{domain}")
            except httpx.HTTPError as exc:
                out.errors.append(f"{domain}: {type(exc).__name__}")
                break
            if resp.status_code == 429:
                out.rate_limited, out.retry_after_s = True, _retry_after(resp)
                break
            if resp.status_code in (200, 204, 404):
                out.removed.append(domain)
            else:
                out.errors.append(f"{domain}: HTTP {resp.status_code}")
        for domain in to_add:
            if out.rate_limited or ops >= self.max_ops:
                break
            ops += 1
            try:
                resp = self._call("POST", "/denylist", {"id": domain, "active": True})
            except httpx.HTTPError as exc:
                out.errors.append(f"{domain}: {type(exc).__name__}")
                break
            if resp.status_code == 429:
                out.rate_limited, out.retry_after_s = True, _retry_after(resp)
                break
            errs = self._errors(resp)
            if resp.status_code in (200, 201, 204) and not errs:
                out.added.append(domain)
            elif any("duplicate" in e.lower() or "exists" in e.lower() for e in errs):
                self.foreign.add(domain)                  # already blocked by an entry we did not add:
                out.already_present.append(domain)        # left alone, and never removed by Daggers
            else:
                out.errors.append(f"{domain}: HTTP {resp.status_code} {', '.join(errs)[:80]}".strip())
        return out

    def blocked_last_24h(self, ttl_s: float = 300.0) -> tuple[int | None, str | None]:
        """Denylist-blocked queries in the last 24 h, from NextDNS analytics. → (count | None, error)."""
        if not self.configured:
            return None, "not configured"
        now = self.clock()
        if self._analytics and now - self._analytics[0] < ttl_s:
            return self._analytics[1], self._analytics[2]
        count, error = None, None
        try:
            resp = self._call("GET", "/analytics/reasons?from=-24h&limit=500")
            if resp.status_code != 200:
                error = f"HTTP {resp.status_code}"
            else:
                data = (resp.json() or {}).get("data") or []
                row = next((r for r in data if str(r.get("id")) == "denylist"), None)
                count = int(row.get("queries") or 0) if row else 0
        except Exception as exc:  # noqa: BLE001
            error = type(exc).__name__
        self._analytics = (now, count, error)
        return count, error


def _retry_after(resp) -> float | None:
    try:
        return float(resp.headers.get("retry-after"))
    except (TypeError, ValueError):
        return None
