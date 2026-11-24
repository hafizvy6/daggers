"""Guard: DNS blocklist generation from the shared Guard feed.

Input is exactly the ``GuardRow`` stream (``runtime.guard_rows()`` — the same
data served at ``/api/guard/feed``). This module does not create another feed.

Only *sufficiently confirmed* malicious domains are blocked:
  * verdict must be ``MALICIOUS`` (confirmed FAKE). ``MISLEADING`` rows are
    never blocked here even if GUARD_BLOCK_MISLEADING is on.
  * domain must be a valid, non-IP DNS name (punycode wire form)
  * rows older than GUARD_MAX_AGE_DAYS are expired
  * anything in the official registry (any status) or the brand allowlist is
    never blocked — a compromised official site is a manual-review case.
Unknown, WARNING, and unverified domains never enter the list.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable

from ..core import homograph
from .official.models import iso, parse_ts, utc_now
from .official.registry import Registry, is_ip_literal, to_ascii_host

DEFAULT_MAX_AGE_DAYS = 30


@dataclass
class BlocklistResult:
    domains: list[str]
    excluded: dict[str, int]
    rows_in: int
    generated_at: str


def build_blocklist(
    rows: Iterable[dict],
    *,
    registry: Registry,
    official_domains: Iterable[str],
    now: datetime,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> BlocklistResult:
    excluded = {"not_malicious": 0, "invalid_domain": 0, "expired": 0, "undated": 0,
                "duplicate": 0, "official_or_registry": 0}
    official = tuple(official_domains)
    out: list[str] = []
    seen: set[str] = set()
    count = 0
    for row in rows:
        count += 1
        if not isinstance(row, dict) or row.get("verdict") != "MALICIOUS":
            excluded["not_malicious"] += 1
            continue
        raw = str(row.get("domain") or "").strip()
        host = to_ascii_host(raw)
        if not host or "." not in host or is_ip_literal(raw) or "*" in raw or "/" in raw or ":" in raw:
            excluded["invalid_domain"] += 1
            continue
        flagged = parse_ts(row.get("flagged_at"))
        if flagged is None:
            excluded["undated"] += 1
            continue
        if flagged - now > timedelta(days=1):  # future-dated rows are not trustworthy
            excluded["undated"] += 1
            continue
        if now - flagged > timedelta(days=max_age_days):
            excluded["expired"] += 1
            continue
        if registry.entries_for_host(host) or any(homograph.is_official_host(host, d) for d in official):
            excluded["official_or_registry"] += 1
            continue
        if host in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(host)
        out.append(host)
    return BlocklistResult(sorted(out), excluded, count, iso(now) or "")


def render(result: BlocklistResult, fmt: str = "hosts") -> str:
    header = [
        "# Daggers Guard blocklist — confirmed-malicious domains only",
        f"# generated_at: {result.generated_at}",
        f"# entries: {len(result.domains)}",
        "# NextDNS: paste the 'domains' format into a denylist, or sync with guard/sync_nextdns.py",
    ]
    if fmt == "domains":
        body = result.domains
    else:
        body = [f"0.0.0.0 {d}" for d in result.domains]
    return "\n".join(header + body) + "\n"


@dataclass
class GuardSync:
    registry: Registry
    official_domains: tuple[str, ...]
    source: Callable[[], list[dict]]
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    min_interval_s: float = 30.0
    clock: Callable[[], datetime] = utc_now
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    last: BlocklistResult | None = None
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None
    consecutive_failures: int = 0

    def sync(self, force: bool = False) -> BlocklistResult | None:
        """Refresh from the shared Guard feed. On failure the previous good list is kept."""
        with self._lock:
            now = self.clock()
            last_ok = parse_ts(self.last_success_at)
            if not force and self.last and last_ok and (now - last_ok).total_seconds() < self.min_interval_s:
                return self.last
            self.last_attempt_at = iso(now)
            try:
                rows = list(self.source())
            except Exception as exc:  # feed unavailable: keep serving last good list
                self.last_error = f"guard feed unavailable ({type(exc).__name__})"
                self.consecutive_failures += 1
                return self.last
            self.last = build_blocklist(rows, registry=self.registry, official_domains=self.official_domains,
                                        now=now, max_age_days=self.max_age_days)
            self.last_success_at = iso(now)
            self.last_error = None
            self.consecutive_failures = 0
            return self.last

    def status(self, mode: str | None = None) -> dict:
        state = "never" if not self.last_attempt_at else ("error" if self.last_error else "ok")
        if self.last_error and self.last:
            state = "stale"
        return {
            "status": state,
            "source": "guard_feed",
            "mode": mode,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "rows_in": self.last.rows_in if self.last else 0,
            "blocked_domains": len(self.last.domains) if self.last else 0,
            "excluded": dict(self.last.excluded) if self.last else {},
            "max_age_days": self.max_age_days,
            "policy": "MALICIOUS only; official/registry domains never blocked",
            "nextdns": {
                "push": "manual script guard/sync_nextdns.py (not run by the server)",
                "block_events_measured": False,
                "note": "Block hit counts are not measured by Daggers; NextDNS free-tier analytics are not read.",
            },
        }
