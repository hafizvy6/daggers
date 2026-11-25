"""'In use since' — the earliest HTTPS certificate logged in public Certificate Transparency (CT).

This is NOT the registration age and is never reported as one. It answers a different question:
"how long has this domain been serving HTTPS?". It matters for TLDs whose registry offers no RDAP
(e.g. `.ae`), where the registration date cannot be looked up.

* Only the ICANN registrable domain is sent (sub-domains included in the search), to the configured
  CT search API (default: SSLMate Cert Spotter, `/v1/issuances`, oldest-discovered first).
* Tenants of shared platforms (shop.github.io) → not_applicable (the platform's history is not theirs).
* Any failure → unknown. Results are cached (7 days; failures 1 h). An API key is optional
  (`CT_API_KEY`); without one the provider allows a limited number of lookups per hour.
* Weakness (documented): CT history does not reset when a domain expires and is re-registered by
  someone else — so it is used only as ONE factor of the established-website rule, together with a
  live HTTPS page and zero warning signs, and only where RDAP is unavailable.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from . import psl as psl_mod

DEFAULT_API = "https://api.certspotter.com/v1/issuances"

OK = "ok"
NONE_FOUND = "no_certificates"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "not_applicable"
DISABLED = "disabled"


@dataclass(frozen=True)
class InUseSince:
    domain: str | None
    status: str
    first_seen: str | None = None
    age_days: int | None = None
    source: str | None = None
    checked_at: str | None = None
    reason: str = ""

    @property
    def known(self) -> bool:
        return self.status == OK and self.age_days is not None

    def as_dict(self) -> dict:
        return {"domain": self.domain, "status": self.status, "first_seen": self.first_seen,
                "age_days": self.age_days, "source": self.source, "checked_at": self.checked_at,
                "reason": self.reason, "basis": "earliest certificate in public Certificate Transparency logs"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(value) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def http_get_json(url: str, timeout: float, api_key: str | None = None, max_bytes: int = 2_000_000):
    headers = {"Accept": "application/json", "User-Agent": "Daggers-CT/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — configured https API
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("CT response too large")
            return resp.status, json.loads(body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


class CTClient:
    def __init__(self, *, enabled: bool = True, api_url: str = DEFAULT_API, api_key: str | None = None,
                 timeout_s: float = 4.0, ok_ttl_s: float = 7 * 86400, fail_ttl_s: float = 3600,
                 fetch: Callable | None = None, psl: psl_mod.PublicSuffixList | None = None,
                 clock: Callable[[], datetime] = _now) -> None:
        self.enabled = enabled
        self.api_url = api_url
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.ok_ttl_s = ok_ttl_s
        self.fail_ttl_s = fail_ttl_s
        self.fetch = fetch or (lambda url, timeout: http_get_json(url, timeout, self.api_key))
        self._psl = psl
        self.clock = clock
        self._cache: dict[str, tuple[float, InUseSince]] = {}
        self._lock = threading.Lock()

    @property
    def psl(self) -> psl_mod.PublicSuffixList:
        return self._psl or psl_mod.default()

    def lookup(self, host: str) -> InUseSince:
        checked = _iso(self.clock())
        host = (host or "").strip().lower().rstrip(".")
        if not self.enabled:
            return InUseSince(None, DISABLED, checked_at=checked, reason="certificate-history lookups are switched off")
        platform = self.psl.platform(host)
        if platform:
            return InUseSince(None, NOT_APPLICABLE, checked_at=checked,
                              reason=f"{host} is a tenant of the shared platform {platform}")
        domain = self.psl.registrable(host)
        if not domain:
            return InUseSince(None, NOT_APPLICABLE, checked_at=checked, reason="not a registrable domain")
        with self._lock:
            cached = self._cache.get(domain)
            if cached and time.time() < cached[0]:
                return cached[1]
        result = self._query(domain, checked)
        ttl = self.ok_ttl_s if result.status in (OK, NONE_FOUND) else self.fail_ttl_s
        with self._lock:
            self._cache[domain] = (time.time() + ttl, result)
        return result

    def _query(self, domain: str, checked: str) -> InUseSince:
        url = f"{self.api_url}?" + urllib.parse.urlencode({"domain": domain, "include_subdomains": "true"})
        source = self.api_url.split("/v1/")[0] if "/v1/" in self.api_url else self.api_url
        try:
            status, payload = self.fetch(url, self.timeout_s)
        except Exception as exc:  # noqa: BLE001
            return InUseSince(domain, UNAVAILABLE, source=source, checked_at=checked,
                              reason=f"certificate-history lookup failed ({type(exc).__name__}) — unknown")
        if status != 200 or not isinstance(payload, list):
            return InUseSince(domain, UNAVAILABLE, source=source, checked_at=checked,
                              reason=f"certificate-history service answered HTTP {status} — unknown")
        dates = [d for d in (_parse(item.get("not_before")) for item in payload if isinstance(item, dict)) if d]
        if not dates:
            return InUseSince(domain, NONE_FOUND, source=source, checked_at=checked,
                              reason="no logged HTTPS certificates — in-use history unknown")
        first = min(dates)
        age = max(0, (self.clock() - first).days)
        return InUseSince(domain, OK, _iso(first), age, source, checked,
                          reason=f"HTTPS certificates logged since {_iso(first)[:10]} ({age // 365} year(s)) — "
                                 "in-use history, not the registration date")
