"""Gather live evidence for ONE link (Checker / investigations): RDAP age, page inspection,
threat-feed lookup — in parallel, under one deadline. Every source reports its own status and
freshness; a missing source is reported as missing, never as a pass.

Privacy: RDAP receives only the registrable domain; the page probe sends one plain GET to the
link itself (no cookies, no Referer, generic User-Agent); feed lookups are local (database).
Nothing about the user (IP, session, browsing) is sent anywhere.
"""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import content as content_mod
from . import psl as psl_mod
from .feeds import FEED_FRESH_HOURS, url_key
from .hostname import HostSignal
from .probe import PageProbe, ProbeResult
from .ct import CTClient, InUseSince
from .rdap import DomainAge, RDAPClient

_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="evidence")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


def _age_hours(ts: str | None, now: datetime) -> float | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return round(max(0.0, (now - dt).total_seconds() / 3600), 2)


@dataclass
class LiveEvidence:
    url: str
    domain_age: DomainAge | None = None
    in_use_since: InUseSince | None = None
    probe: ProbeResult | None = None
    feed: dict | None = None
    signals: list[HostSignal] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)

    @property
    def final_host(self) -> str | None:
        return self.probe.final_host if self.probe else None

    def context(self) -> dict:
        ctx: dict = {"extra_signals": [s.as_context() for s in self.signals]}
        if self.domain_age and self.domain_age.known:
            ctx["domain_age_days"] = self.domain_age.age_days
        return ctx

    def summary(self) -> dict:
        return {
            "domain_age": self.domain_age.as_dict() if self.domain_age else None,
            "in_use_since": self.in_use_since.as_dict() if self.in_use_since else None,
            "page": self.probe.as_dict() if self.probe else None,
            "feeds": self.feed,
        }


class EvidenceGatherer:
    def __init__(self, *, rdap: RDAPClient | None, probe: PageProbe | None, repo=None,
                 deadline_s: float = 10.0, ct: CTClient | None = None) -> None:
        self.rdap = rdap
        self.ct = ct
        self.probe = probe
        self.repo = repo
        self.deadline_s = deadline_s

    def _feed(self, url: str, host: str) -> dict:
        now = _now()
        if self.repo is None:
            return {"status": "unavailable", "reason": "no feed store"}
        keyed = url_key(url)
        if not keyed:
            return {"status": "not_applicable", "reason": "no URL"}
        key, khost = keyed
        site = psl_mod.default().site(khost) or khost
        hit = self.repo.feed_lookup(key, khost, site)
        updated = self.repo.feed_freshness()
        age = _age_hours(updated, now)
        if updated is None:
            status, reason = "no_data", "no threat-feed data has been downloaded — not checked"
        elif age is not None and age > FEED_FRESH_HOURS:
            status, reason = "stale", f"threat-feed data is {age:.0f} h old — a miss proves nothing"
        else:
            status, reason = "checked", "checked against threat feeds (a miss is not proof of safety)"
        return {**hit, "status": status, "reason": reason, "data_updated_at": updated, "data_age_hours": age}

    def gather(self, url: str, host: str, *, registry, brands=(), host_authenticated=lambda h: False,
               host_is_shared=lambda h: False) -> LiveEvidence:
        ev = LiveEvidence(url)
        jobs = {}
        if self.rdap is not None:
            jobs["rdap"] = _POOL.submit(self.rdap.lookup, host)
        if self.probe is not None:
            jobs["probe"] = _POOL.submit(self.probe.probe, url)
        if self.ct is not None:
            jobs["ct"] = _POOL.submit(self.ct.lookup, host)
        jobs["feed"] = _POOL.submit(self._feed, url, host)
        done, _ = concurrent.futures.wait(jobs.values(), timeout=self.deadline_s)
        for name, fut in jobs.items():
            if fut not in done:
                continue
            try:
                value = fut.result()
            except Exception:  # noqa: BLE001 — one source failing never breaks the check
                continue
            if name == "rdap":
                ev.domain_age = value
            elif name == "ct":
                ev.in_use_since = value
            elif name == "probe":
                ev.probe = value
            else:
                ev.feed = value
        now = _now()
        psl = psl_mod.default()
        # ---- signals (each carries its evidence group)
        if ev.probe is not None:
            final = ev.probe.final_host or host
            ev.signals += content_mod.page_signals(ev.probe, host_authenticated=bool(host_authenticated(final)),
                                                   registry=registry, brands=brands, psl=psl)
            ev.signals += content_mod.redirect_signals(ev.probe, psl)
        if ev.feed:
            ev.signals += content_mod.feed_signals(ev.feed, host_is_shared=bool(host_is_shared(host)))
        # ---- evidence records with freshness (shown in the Checker / Portal)
        da = ev.domain_age
        ev.records.append({
            "id": "domain_age", "source": "RDAP (IANA bootstrap)",
            "status": da.status if da else "timeout",
            "checked_at": da.checked_at if da else _iso(now),
            "summary": (da.reason if da else "lookup did not finish in time — age unknown"),
            "observed": {"domain": da.domain, "registered_at": da.registered_at, "age_days": da.age_days} if da else None,
        })
        if self.ct is not None:
            us = ev.in_use_since
            ev.records.append({
                "id": "in_use_since", "source": "Certificate Transparency logs",
                "status": us.status if us else "timeout", "checked_at": us.checked_at if us else _iso(now),
                "summary": us.reason if us else "lookup did not finish in time — unknown",
                "observed": {"domain": us.domain, "first_seen": us.first_seen, "age_days": us.age_days} if us else None,
            })
        pr = ev.probe
        ev.records.append({
            "id": "page", "source": "secure page retrieval (markup only)",
            "status": pr.status if pr else ("timeout" if self.probe is not None else "disabled"),
            "checked_at": (pr.retrieved_at if pr else _iso(now)),
            "summary": (pr.reason if pr else "page retrieval did not finish in time"),
            "observed": ({"final_host": pr.final_host, "redirected": pr.redirected_off_host,
                          "hops": len(pr.hops)} if pr else None),
        })
        fd = ev.feed or {"status": "timeout", "reason": "feed lookup did not finish"}
        ev.records.append({
            "id": "feeds", "source": "phishing / malware feeds",
            "status": fd.get("status"), "checked_at": _iso(now),
            "data_updated_at": fd.get("data_updated_at"), "data_age_hours": fd.get("data_age_hours"),
            "summary": ("this exact URL is listed" if fd.get("url_listed") else
                        "other URLs on this host are listed" if fd.get("host_listed") else fd.get("reason")),
        })
        return ev
