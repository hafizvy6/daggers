"""Guard live loop: Checker / Radar / Sweep / Investigation → eligibility → DB + O(1) index →
debounced sync (providers) → SSE. Every number it reports is counted, never invented."""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from . import eligibility
from .index import GuardIndex
from .nextdns import NextDNSProvider

logger = logging.getLogger("daggers.guard")


class SyncCooldown(Exception):
    def __init__(self, retry_after_s: int) -> None:
        super().__init__(f"sync cooldown: retry in {retry_after_s}s")
        self.retry_after_s = retry_after_s


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(ts) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class GuardManager:
    def __init__(self, *, repo, settings, publish: Callable[[str, dict], None],
                 registry_fn: Callable, official_domains_fn: Callable, reputation_fn: Callable,
                 tag_fn: Callable[[dict], dict], provider: NextDNSProvider | None = None,
                 clock: Callable[[], datetime] = _now) -> None:
        self.repo = repo
        self.settings = settings
        self.publish = publish
        self.registry_fn = registry_fn
        self.official_domains_fn = official_domains_fn
        self.reputation_fn = reputation_fn
        self.tag_fn = tag_fn
        self.clock = clock
        self.index = GuardIndex()
        self.provider = provider if provider is not None else NextDNSProvider(
            settings.nextdns_profile, settings.nextdns_api_key)
        self._timer: threading.Timer | None = None
        self._timer_lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self._last_manual = 0.0
        self.state: dict = {"last_attempt_at": None, "last_success_at": None, "last_error": None,
                            "last_push": None, "rate_limited_until": None, "syncs": 0}
        self.warmed = False

    # ------------------------------------------------------------------ helpers

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.settings, "guard_enabled", True))

    def _decide(self, item: dict, source: str) -> eligibility.Decision:
        return eligibility.evaluate(
            item, source=source, registry=self.registry_fn(), official_domains=self.official_domains_fn(),
            reputation=self.reputation_fn(), include_misleading=bool(self.settings.guard_block_misleading))

    @staticmethod
    def source_of(finding: dict) -> str:
        raw = str(finding.get("source") or "radar").lower()
        for name in ("checker", "investigation", "sweep", "radar", "seed"):
            if raw.startswith(name):
                return name
        return "radar"

    # ------------------------------------------------------------------ boot

    def warm(self) -> None:
        """Load the persisted list into the index, then reconcile with stored findings."""
        self.index.replace(self.repo.guard_list_rows())
        self.warmed = True
        try:
            self.reconcile()
        except Exception:  # noqa: BLE001 — a reconcile problem must never stop the server
            logger.exception("Guard reconcile failed at start-up")
        if self.enabled:
            self.schedule_sync()          # first sync shortly after start-up (provider push + health)

    # ------------------------------------------------------------------ live loop

    def offer(self, item: dict, source: str, finding_id: int | None = None, *, quiet: bool = False) -> dict:
        """A new analysis (Checker / Radar / Sweep / Investigation). Lists it if eligible; removes an
        existing listing when the domain is protected or a newer analysis says SAFE."""
        if not self.enabled or item is None:
            return {"listed": False, "reason": "Guard is switched off"}
        if source not in tuple(getattr(self.settings, "guard_sources", ()) or ()):
            return {"listed": False, "reason": f"{source} analyses do not feed the Guard (GUARD_SOURCES)"}
        decision = self._decide(item, source)
        if decision.eligible:
            reasons = item.get("trust_reasons") or item.get("reasons") or []
            entry = {"domain": decision.domain, "source": source, "finding_id": finding_id or item.get("id"),
                     "tag": str(item.get("tag")), "verdict": str(item.get("verdict")),
                     "score": float(item.get("score") or item.get("risk_score") or 0.0),
                     "reason": next((str(r) for r in reasons if "not an authenticated" not in str(r)),
                                    "confirmed malicious")}
            new = self.repo.guard_upsert(entry)
            row = self.repo.guard_get(decision.domain)
            if row:
                self.index.put(row)
            if new and not quiet and source != "investigation":  # investigations never reach the public stream
                self.publish("guard", {"type": "listed", "domain": decision.domain, "source": source,
                                       "score": entry["score"], "reason": entry["reason"],
                                       "listed_at": row["listed_at"] if row else None,
                                       "finding_id": _public_id(source, entry["finding_id"]),
                                       "blocklist_count": len(self.index)})
            if new:
                self.schedule_sync()
            return {"listed": True, "new": new, "domain": decision.domain, "scope": decision.scope,
                    "reason": decision.reason, "listed_at": row["listed_at"] if row else None}
        host = eligibility.normalize_host(item.get("domain") or item.get("host") or "")
        if host and host.startswith("www."):
            host = host[4:] if self.index.match(host[4:]) else host
        if host and host in set(self.index.domains()):
            if decision.protected:
                self.delist(host, decision.reason)
            elif str(item.get("tag")).upper() == "SAFE":
                self.delist(host, "a newer analysis found it SAFE")
        return {"listed": False, "reason": decision.reason}

    def delist(self, domain: str, reason: str, *, quiet: bool = False) -> bool:
        removed = self.repo.guard_delist(domain, reason)
        self.index.drop(domain)
        if removed and not quiet:
            self.publish("guard", {"type": "delisted", "domain": domain, "reason": reason,
                                   "blocklist_count": len(self.index)})
            self.schedule_sync()
        return removed

    def reconcile(self) -> dict:
        """Re-derive the list: list eligible stored findings, remove protected / expired entries."""
        added = removed = 0
        verdicts = ["MALICIOUS"] + (["MISLEADING"] if self.settings.guard_block_misleading else [])
        max_age = timedelta(days=int(self.settings.guard_max_age_days or 30))
        now = self.clock()
        listed = set(self.index.domains())
        for finding in self.repo.guard_candidates(verdicts):
            created = _parse(finding.get("created_at") or finding.get("first_seen"))
            if created is None or now - created > max_age or created - now > timedelta(days=1):
                continue                                  # undated, too old or future-dated: never (re)listed
            if eligibility.normalize_host(finding.get("domain") or "") in listed:
                continue                                  # already listed: its age is not reset
            try:
                tagged = self.tag_fn(finding) or finding
            except Exception:  # noqa: BLE001
                continue
            source = self.source_of(tagged)
            if source == "checker" and not tagged.get("input_type"):
                continue
            result = self.offer(tagged, source, int(tagged.get("id") or 0) or None, quiet=True)
            added += int(bool(result.get("new")))
        for row in self.index.rows():
            updated = _parse(row.get("updated_at")) or _parse(row.get("listed_at"))
            if updated and now - updated > max_age:
                removed += int(self.delist(row["domain"], f"expired (older than {max_age.days} days)", quiet=True))
                continue
            check = self._decide({"tag": row["tag"], "verdict": row["verdict"], "domain": row["domain"],
                                  "input_type": "url"}, "seed")
            if not check.eligible and check.protected:
                removed += int(self.delist(row["domain"], check.reason, quiet=True))
        return {"added": added, "removed": removed, "active": len(self.index)}

    # ------------------------------------------------------------------ sync

    def stop(self) -> None:
        """Cancel pending timers (server shutdown): no sync may run after the database is closed."""
        self._stopped = True
        with self._timer_lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def schedule_sync(self) -> None:
        if getattr(self, "_stopped", False):
            return
        delay = float(getattr(self.settings, "guard_sync_debounce_s", 3.0))
        with self._timer_lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(delay, self._timed_sync)
            self._timer.daemon = True
            self._timer.name = "guard-sync"
            self._timer.start()

    def _timed_sync(self) -> None:
        if getattr(self, "_stopped", False):
            return
        try:
            self.sync()
        except Exception:  # noqa: BLE001
            logger.exception("Guard sync failed")

    def manual_sync(self) -> dict:
        cooldown = float(getattr(self.settings, "guard_sync_cooldown_s", 30.0))
        now = time.monotonic()
        if now - self._last_manual < cooldown:
            raise SyncCooldown(int(cooldown - (now - self._last_manual)) + 1)
        self._last_manual = now
        return self.sync(manual=True)

    def sync(self, manual: bool = False) -> dict:
        with self._sync_lock:
            now = self.clock()
            self.state["last_attempt_at"] = _iso(now)
            recon = self.reconcile()
            push = None
            error = None
            until = _parse(self.state.get("rate_limited_until"))
            if self.provider.configured and not (until and until > now):
                desired = set(self.index.domains())
                pushed = self.repo.guard_pushed(self.provider.name)
                result = self.provider.push(desired, pushed)
                self.repo.guard_mark_pushed(self.provider.name, result.added, result.removed)
                push = result.as_dict()
                push["managed_entries"] = len(self.repo.guard_pushed(self.provider.name))
                if result.rate_limited:
                    wait = result.retry_after_s or 60
                    self.state["rate_limited_until"] = _iso(now + timedelta(seconds=wait))
                    self.schedule_later(wait + 1)
                if result.errors:
                    error = "; ".join(result.errors[:3])
            self.state["last_push"] = push
            self.state["last_error"] = error
            if not error:
                self.state["last_success_at"] = _iso(now)
            self.state["syncs"] += 1
            self.repo.guard_log_event("sync", {"manual": manual, "active": len(self.index),
                                               "push": push, "error": error, **recon})
            self.publish("guard", {"type": "sync", "blocklist_count": len(self.index),
                                   "health": self.sync_health(), "at": _iso(now)})
            return {**self.sync_status(), "ok": error is None}

    def schedule_later(self, seconds: float) -> None:
        timer = threading.Timer(seconds, self._timed_sync)
        timer.daemon = True
        timer.name = "guard-sync"
        timer.start()

    def sync_health(self) -> str:
        until = _parse(self.state.get("rate_limited_until"))
        if until and until > self.clock():
            return "rate_limited"
        if not self.state.get("last_attempt_at"):
            return "never"
        return "error" if self.state.get("last_error") else "ok"

    # ------------------------------------------------------------------ blocks (real hits)

    def record_block(self, domain: str) -> None:
        day = self.clock().strftime("%Y-%m-%d")
        today, total = self.repo.guard_record_block(domain, day)
        self.publish("guard", {"type": "hit", "domain": domain, "blocked_today": today, "blocked_total": total})

    # ------------------------------------------------------------------ queries

    def check(self, raw: str) -> dict:
        host = eligibility.normalize_host(raw)
        if host is None:
            return {"domain": str(raw)[:253], "valid": False, "blocked": False,
                    "reason": "not a valid domain name"}
        row = self.index.match(host)
        return {"domain": host, "valid": True, "blocked": row is not None,
                "matched": row["domain"] if row else None, "source": row["source"] if row else None,
                "listed_at": row["listed_at"] if row else None, "reason": row["reason"] if row else None,
                "finding_id": _public_id(row["source"], row["finding_id"]) if row else None}

    def feed_rows(self) -> list[dict]:
        """C6 GuardRow shape: {domain, verdict, reason, flagged_at}."""
        return [{"domain": r["domain"], "verdict": r["verdict"], "reason": r["reason"],
                 "flagged_at": r["listed_at"]} for r in sorted(self.index.rows(), key=lambda r: r["listed_at"],
                                                               reverse=True)]

    def mode(self) -> str:
        s = self.settings
        if getattr(s, "guard_doh_enabled", False) and getattr(s, "guard_verdict_ip", ""):
            return "doh_verdict"
        if getattr(s, "guard_doh_enabled", False):
            return "doh"
        if self.provider.configured:
            return "nextdns"
        return "list_only"

    def stats(self, origin: str) -> dict:
        today, total = self.repo.guard_block_counts(self.clock().strftime("%Y-%m-%d"))
        s = self.settings
        nd_count, nd_error = (None, None)
        if self.provider.configured:
            nd_count, nd_error = self.provider.blocked_last_24h()
        rows = sorted(self.index.rows(), key=lambda r: r["listed_at"], reverse=True)
        count = len(rows)
        return {
            # original keys (C-contract) — kept
            "blocked_domains": count, "feed_size": count, "blocked_hits": total, "blocked_today": today,
            "mode": "live",
            # live Guard
            "status": "on" if self.enabled else "off",
            "enabled": self.enabled,
            "guard_mode": self.mode(),
            "dot_hostname": s.guard_dns_hostname or None,
            "doh_url": f"{origin}/dns-query" if getattr(s, "guard_doh_enabled", False) else None,
            "blocklist_url": f"{origin}/api/guard/blocklist.txt",
            "domains_url": f"{origin}/api/guard/domains.txt",
            "adguard_url": f"{origin}/api/guard/adguard-rules.txt",
            "blocklist_count": count,
            "blocked_total": total,
            "blocked_counted_from": "DNS-over-HTTPS blocks and verdict-page visits on this server",
            "nextdns_configured": self.provider.configured,
            "nextdns_blocked_24h": nd_count,
            "nextdns_blocked_24h_error": nd_error,
            "newest_fakes": [{**{k: r.get(k) for k in ("domain", "source", "score", "reason", "listed_at")},
                              "finding_id": _public_id(r.get("source"), r.get("finding_id"))}
                             for r in rows[:10]],
            "last_sync_at": self.state.get("last_success_at"),
            "sync_health": self.sync_health(),
            "honest_limits_key": f"guard.limits_{self.mode()}",
        }

    def sync_status(self) -> dict:
        last = self.repo.guard_last_event("sync")
        return {
            "status": {"ok": "ok", "never": "never", "error": "error", "rate_limited": "stale"}[self.sync_health()],
            "source": "guard_feed",
            "mode": self.mode(),
            "enabled": self.enabled,
            "feed_count": len(self.index),
            "blocked_domains": len(self.index),
            "last_attempt_at": self.state.get("last_attempt_at"),
            "last_success_at": self.state.get("last_success_at"),
            "last_error": self.state.get("last_error"),
            "rate_limited_until": self.state.get("rate_limited_until"),
            "last_sync_event": last,
            "max_age_days": int(self.settings.guard_max_age_days or 30),
            "policy": "confirmed FAKE (MALICIOUS) only; official, registry, shared and widely used domains never blocked",
            "nextdns": {
                "configured": self.provider.configured,
                "push": "automatic (debounced) on every list change" if self.provider.configured
                        else "not configured (set NEXTDNS_PROFILE_ID and NEXTDNS_API_KEY)",
                "last_push": self.state.get("last_push"),
                "managed_entries": len(self.repo.guard_pushed(self.provider.name)),
                "pull_url": "/api/guard/domains.txt",
                "block_events_measured": bool(self.provider.configured and
                                              self.provider._analytics and self.provider._analytics[1] is not None),
            },
        }


PRIVATE_SOURCES = ("checker", "investigation")


def _public_id(source, finding_id):
    """Citizen submissions and investigations stay portal-only: their finding id is never published."""
    return None if str(source or "") in PRIVATE_SOURCES else finding_id


def client_key(ip: str) -> str:
    """Rate-limit key for a client: a salted hash kept in memory only (never stored or logged)."""
    return hashlib.sha256(f"guard-rl\n{ip}".encode()).hexdigest()[:20]
