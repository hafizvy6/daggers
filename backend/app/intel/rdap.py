"""Domain REGISTRATION age via RDAP (RFC 9082/9083), using the IANA bootstrap (RFC 9224).

Rules (by design, not configuration):

* Only the public REGISTRABLE domain is sent (``adpolice.gov.ae`` for ``es.adpolice.gov.ae/x?y``),
  and only to the RDAP server IANA lists for that TLD. Never the URL, path, query or sub-domain.
* Only the ``registration`` event counts. Certificate age, DNS age and the RDAP ``last changed`` /
  ``expiration`` events are never used as registration age.
* A failed, unsupported or missing lookup is ``age unknown`` — not "new", not "old", not "safe".
* A tenant of a shared platform (``shop.github.io``) gets ``not_applicable``: the platform's
  registration age says nothing about the tenant.
* The age is evidence only. A young domain is a WEAK signal that counts only next to independent
  evidence (``core.scorer``); an old domain never earns SAFE and never cancels a fraud signal.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import psl as psl_mod

logger = logging.getLogger("daggers.rdap")

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
NEW_DOMAIN_DAYS = 30            # "recently registered" threshold for the weak signal

OK = "ok"
NOT_FOUND = "not_found"
NO_SERVICE = "no_rdap_service"
NO_EVENT = "no_registration_event"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "not_applicable"
DISABLED = "disabled"


@dataclass(frozen=True)
class DomainAge:
    domain: str | None
    status: str
    registered_at: str | None = None
    age_days: int | None = None
    source: str | None = None
    checked_at: str | None = None
    reason: str = ""
    registrar: str | None = None

    @property
    def known(self) -> bool:
        return self.status == OK and self.age_days is not None

    @property
    def recently_registered(self) -> bool:
        return self.known and self.age_days < NEW_DOMAIN_DAYS   # type: ignore[operator]

    def as_dict(self) -> dict:
        return {"domain": self.domain, "status": self.status, "registered_at": self.registered_at,
                "age_days": self.age_days, "source": self.source, "checked_at": self.checked_at,
                "reason": self.reason, "registrar": self.registrar, "basis": "RDAP registration event"}


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


def registration_date(payload: dict) -> datetime | None:
    """ONLY eventAction == 'registration'. 'last changed', 'expiration', 'transfer' … are ignored."""
    for event in payload.get("events") or []:
        if str(event.get("eventAction", "")).strip().lower() == "registration":
            return _parse(event.get("eventDate"))
    return None


def registrar_name(payload: dict) -> str | None:
    for entity in payload.get("entities") or []:
        if "registrar" in {str(r).lower() for r in entity.get("roles") or []}:
            vcard = entity.get("vcardArray") or []
            props = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
            for prop in props:
                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                    return str(prop[3])[:120]
    return None


def http_get_json(url: str, timeout: float, max_bytes: int = 512_000) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                               "User-Agent": "Daggers-RDAP/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https URLs from IANA only
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("RDAP response too large")
            return resp.status, json.loads(body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


class RDAPClient:
    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        enabled: bool = True,
        timeout_s: float = 4.0,
        ok_ttl_s: float = 7 * 86400,
        fail_ttl_s: float = 3600,
        bootstrap_max_age_s: float = 30 * 86400,
        fetch: Callable[[str, float], tuple[int, dict | None]] = http_get_json,
        psl: psl_mod.PublicSuffixList | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.enabled = enabled
        self.timeout_s = timeout_s
        self.ok_ttl_s = ok_ttl_s
        self.fail_ttl_s = fail_ttl_s
        self.bootstrap_max_age_s = bootstrap_max_age_s
        self.fetch = fetch
        self._psl = psl
        self.clock = clock
        self._bootstrap: dict[str, list[str]] | None = None
        self._bootstrap_at = 0.0
        self._cache: dict[str, tuple[float, DomainAge]] = {}
        self._lock = threading.Lock()

    @property
    def psl(self) -> psl_mod.PublicSuffixList:
        return self._psl or psl_mod.default()

    # ------------------------------------------------------------------ bootstrap (IANA)

    def _bootstrap_path(self) -> Path | None:
        return self.cache_dir / "rdap-bootstrap-dns.json" if self.cache_dir else None

    def _load_bootstrap(self) -> dict[str, list[str]] | None:
        now = time.time()
        if self._bootstrap is not None and now - self._bootstrap_at < self.bootstrap_max_age_s:
            return self._bootstrap
        path = self._bootstrap_path()
        data = None
        if path and path.exists() and now - path.stat().st_mtime < self.bootstrap_max_age_s:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
        if data is None:
            try:
                status, data = self.fetch(BOOTSTRAP_URL, self.timeout_s)
            except Exception as exc:  # noqa: BLE001
                logger.info("RDAP bootstrap unavailable (%s)", exc)
                return self._bootstrap         # keep an older copy in memory if we have one
            if status != 200 or not isinstance(data, dict):
                return self._bootstrap
            if path:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        json.dump(data, fh)
                    os.replace(tmp, path)
                except OSError:
                    pass
        table: dict[str, list[str]] = {}
        for service in data.get("services") or []:
            if not isinstance(service, list) or len(service) < 2:
                continue
            urls = [u for u in service[1] if isinstance(u, str) and u.startswith("https://")]
            for tld in service[0]:
                table[str(tld).lower()] = urls
        self._bootstrap, self._bootstrap_at = table, now
        return table

    # ------------------------------------------------------------------ lookup

    def registrable(self, host: str) -> tuple[str | None, str | None]:
        """→ (ICANN registrable domain, reason it is not applicable)."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return None, "no host"
        try:
            import ipaddress
            ipaddress.ip_address(host.strip("[]"))
            return None, "IP address — no domain registration"
        except ValueError:
            pass
        platform = self.psl.platform(host)
        if platform:
            return None, (f"{host} is a tenant of the shared platform {platform}; the platform's registration "
                          "age says nothing about this site")
        reg = self.psl.registrable(host)
        if not reg:
            return None, "not a registrable domain"
        return reg, None

    def lookup(self, host: str) -> DomainAge:
        checked = _iso(self.clock())
        domain, why_not = self.registrable(host)
        if not self.enabled:
            return DomainAge(domain, DISABLED, checked_at=checked, reason="domain-age lookups are switched off")
        if domain is None:
            return DomainAge(None, NOT_APPLICABLE, checked_at=checked, reason=why_not or "")
        with self._lock:
            cached = self._cache.get(domain)
            if cached and time.time() < cached[0]:
                return cached[1]
        result = self._query(domain, checked)
        ttl = self.ok_ttl_s if result.status in (OK, NOT_FOUND, NO_SERVICE, NO_EVENT) else self.fail_ttl_s
        with self._lock:
            self._cache[domain] = (time.time() + ttl, result)
        return result

    def _query(self, domain: str, checked: str) -> DomainAge:
        tld = domain.rsplit(".", 1)[-1]
        table = self._load_bootstrap()
        if table is None:
            return DomainAge(domain, UNAVAILABLE, checked_at=checked,
                             reason="RDAP bootstrap (IANA) could not be retrieved — age unknown")
        bases = table.get(tld)
        if not bases:
            return DomainAge(domain, NO_SERVICE, checked_at=checked,
                             reason=f"the .{tld} registry publishes no RDAP service — age unknown")
        base = bases[0].rstrip("/") + "/"
        url = f"{base}domain/{domain}"
        try:
            status, payload = self.fetch(url, self.timeout_s)
        except Exception as exc:  # noqa: BLE001 — network, TLS, timeout, bad JSON
            return DomainAge(domain, UNAVAILABLE, source=base, checked_at=checked,
                             reason=f"RDAP lookup failed ({type(exc).__name__}) — age unknown")
        if status == 404:
            return DomainAge(domain, NOT_FOUND, source=base, checked_at=checked,
                             reason="the registry has no record of this domain — age unknown")
        if status != 200 or not isinstance(payload, dict):
            return DomainAge(domain, UNAVAILABLE, source=base, checked_at=checked,
                             reason=f"RDAP server answered HTTP {status} — age unknown")
        registered = registration_date(payload)
        if registered is None:
            return DomainAge(domain, NO_EVENT, source=base, checked_at=checked,
                             reason="the RDAP record has no registration date — age unknown")
        age = max(0, (self.clock() - registered).days)
        return DomainAge(domain, OK, _iso(registered), age, base, checked,
                         reason=(f"registered {age} day(s) ago ({age // 365} year(s)) — established domain; this is "
                                 "context only, not proof of safety" if age >= 365 else
                                 f"registered {age} day(s) ago"), registrar=registrar_name(payload))
