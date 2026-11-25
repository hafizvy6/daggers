from __future__ import annotations

import asyncio
import secrets
import threading
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import security
from .api import auth, findings, guard, health, investigations, reports, scan, stream, sweep
from .api import ai as ai_api
from .api import check as check_api
from .api import examples
from .api import system
from .catalog import load_catalogs
from .channels import urls as channel_urls
from .channels.scoring import ShieldScorer
from .channels.official import POLICY_VERSION
from .channels.official.registry import DEFAULT_REGISTRY_PATH, Registry
from . import checker_store as checker_store_lib
from .build import fingerprint as build_fingerprint
from .channels.reputation import Reputation
from .guard.manager import GuardManager
from .intel.ct import CTClient
from .intel.evidence import EvidenceGatherer
from .intel.probe import PageProbe
from .intel.rdap import RDAPClient
from .channels.reputation import update as reputation_update
from .config import Heartbeats, Settings
from .core import scorer, verdicts
from .db.repo import Repository, finding_with_detail, utc_now
from .radar.pipeline import RadarPipeline
from .reports.queue import ReportQueue
from .channels.official.snapshots import SnapshotStore
from . import checker as checker_lib
from .main_errors import CheckFailed

logger = logging.getLogger("daggers.app")


class _PrivateAccessLogFilter(logging.Filter):
    """The DoH resolver and the verdict page must not leave a browsing history in the server log:
    uvicorn's access log would record the client address and the queried name (GET ?dns=…)."""

    PRIVATE = ("/dns-query", "/api/guard/verdict", "/verdict", "/api/guard/check")

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args if isinstance(record.args, tuple) else ()
        path = str(args[2]) if len(args) >= 3 else ""
        return not path.split("?", 1)[0].startswith(self.PRIVATE)


def _install_access_log_filter() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _PrivateAccessLogFilter) for f in access.filters):
        access.addFilter(_PrivateAccessLogFilter())


def _live_records(provider):
    """Synthetic (test) records are never used by the running application."""

    def provide(entries):
        return [record for record in provider(entries) if not getattr(record, "synthetic", False)]

    return provide


def sse(event: str, data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n"


class EventBus:
    def __init__(self, maxsize: int = 100) -> None:
        self.maxsize = maxsize
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: str, data: dict) -> None:
        message = {"event": event, "data": data}
        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(message)
                except asyncio.QueueFull:
                    pass


class Runtime:
    """Application state shared by every route; routes contain no business logic.

    The ONE verdict path: WS1 brain (core.scorer) → WS2 trust policy (ShieldScorer)
    → tag. Every surface (scan, feed, finding, investigation, sweep, guard, portal,
    extension) reads tags produced here.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self.started_at = time.monotonic()
        self.repo = Repository(self.settings)
        # The Checker's own result store (separate file; never the Portal database). Opened on the
        # first check, so importing the app never creates files.
        self._checker_store: checker_store_lib.CheckerStore | None = None
        self._checker_store_lock = threading.Lock()
        self.catalog = load_catalogs()
        self.heartbeats = Heartbeats()
        self.events = EventBus()
        self.mode = "live"  # the only mode
        self.local_csrf_token = secrets.token_urlsafe(32)   # LOCAL_OPEN_ACCESS (dev) only
        self._registry_checked_at = 0.0
        self._registry_mtime: tuple[str, int] | None = None
        self.registry_error: str | None = None
        self._reputation_mtime: int | None = None
        self._reputation_lock = threading.Lock()
        self.reputation_update_error: str | None = None
        self.trust_policy: ShieldScorer | None = self._load_trust_policy()
        self._loop: asyncio.AbstractEventLoop | None = None
        self.guard = GuardManager(
            repo=self.repo, settings=self.settings, publish=self.publish,
            registry_fn=lambda: self.trust_policy.registry if self.trust_policy else None,
            official_domains_fn=lambda: tuple(self.catalog.official_domains),
            reputation_fn=lambda: self.trust_policy.reputation if self.trust_policy else None,
            tag_fn=self.tag,
        )
        self.login_failures = security.SlidingWindow(self.settings.login_max_failures, 15 * 60)
        self.scan_limiter = security.SlidingWindow(self.settings.scan_rate_per_min, 60)
        self.report_queue = ReportQueue(self.repo, clone_min=self.settings.autofile_clone_min)
        self.pipeline = RadarPipeline(
            repo=self.repo,
            settings=self.settings,
            catalog=self.catalog,
            report_queue=self.report_queue,
            publish=self.publish,
            heartbeats=self.heartbeats,
            status_getter=self.status,
        )

    def _load_trust_policy(self) -> ShieldScorer | None:
        try:
            # Official records come ONLY from the snapshot store, which holds what the
            # registry CLI actually retrieved from approved sources (`... cli fetch <id>`).
            # Nothing retrieved → claims are reported as not checked, never as verified.
            store = SnapshotStore(self.settings.official_snapshot_dir)
            registry = Registry.load(self.settings.official_registry_path or DEFAULT_REGISTRY_PATH)
            scorer_ = ShieldScorer(catalog=self.catalog, thresholds=self.settings.thresholds, registry=registry,
                                   record_provider=_live_records(store.provider()),
                                   reputation=self._load_reputation())
            scorer_.gatherer = self._make_gatherer()
            return scorer_
        except Exception as exc:  # invalid registry/lexicon: fail closed (no SAFE anywhere), keep serving
            logger.error("Trust policy failed to load (%s); no result will be tagged SAFE", exc)
            return None

    def _make_gatherer(self) -> EvidenceGatherer:
        """Live Checker evidence. Feed lookups are local and always on; RDAP and page retrieval
        follow CHECK_RDAP_ENABLED / CHECK_PAGE_FETCH_ENABLED (a disabled source is reported as such)."""
        s = self.settings
        rdap = RDAPClient(cache_dir=s.db_path.parent if s.db_path else None, enabled=s.check_rdap_enabled,
                          timeout_s=min(4.0, s.check_evidence_deadline_s))
        probe = PageProbe(enabled=s.check_page_fetch_enabled,
                          total_timeout_s=min(8.0, s.check_evidence_deadline_s))
        ct = CTClient(enabled=s.check_ct_enabled, api_url=s.ct_api_url, api_key=s.ct_api_key or None,
                      timeout_s=min(4.0, s.check_evidence_deadline_s))
        return EvidenceGatherer(rdap=rdap, probe=probe, repo=self.repo, deadline_s=s.check_evidence_deadline_s, ct=ct)

    # ------------------------------------------------------------- site reputation (Tranco)

    def _load_reputation(self) -> Reputation | None:
        path = self.settings.reputation_list_path
        if path is None:
            return None
        try:
            self._reputation_mtime = path.stat().st_mtime_ns
        except OSError:
            self._reputation_mtime = -1
        return Reputation.load(path, top_n=self.settings.reputation_top_n,
                               max_age_days=self.settings.reputation_max_age_days)

    def maybe_reload_reputation(self) -> bool:
        """Pick up a newly downloaded list without a restart. Corrupt list → nothing reputable."""
        if self.trust_policy is None or self.trust_policy.reputation is None:
            return False
        if self.settings.reputation_list_path is None:
            return False
        try:
            mtime = self.settings.reputation_list_path.stat().st_mtime_ns
        except OSError:
            mtime = -1
        if mtime == getattr(self, "_reputation_mtime", None):
            return False
        previous = self.trust_policy.reputation_version
        self.trust_policy.reputation = self._load_reputation()
        if self.trust_policy.reputation_version != previous:
            logger.info("Reputation list reloaded: %s → %s", previous, self.trust_policy.reputation_version)
            self._reconcile_async()
            return True
        return False

    def update_reputation(self) -> dict | None:
        """Download the Tranco list (+ Public Suffix List). Errors leave the current list in place."""
        if self.settings.reputation_list_path is None:
            return None
        with self._reputation_lock:
            try:
                meta = reputation_update(self.settings.reputation_list_path, top_n=self.settings.reputation_top_n)
                self.reputation_update_error = None
                logger.info("Reputation list %s installed (%s domains)", meta["list_id"], meta["rows"])
            except Exception as exc:  # noqa: BLE001 — network/format problems must not crash the app
                self.reputation_update_error = str(exc)[:300]
                logger.warning("Reputation list download failed (%s); keeping the current list", exc)
                return None
        self._registry_checked_at = 0.0
        self.maybe_reload_reputation()
        return meta

    def _reputation_auto_update(self) -> None:
        rep = self.trust_policy.reputation if self.trust_policy else None
        if rep is not None and self.settings.reputation_auto_update and rep.needs_refresh(7):
            threading.Thread(target=self.update_reputation, name="reputation-update", daemon=True).start()

    async def start(self) -> None:
        if self.settings.local_open_access:
            logger.warning("LOCAL_OPEN_ACCESS is ON: browsers on this machine get admin access without "
                           "signing in. Development only; it is always off with APP_ENV=production.")
        # Boot creates the schema only. It never inserts product data.
        self.repo.initialize()
        self.repo.set_meta("mode", self.mode)
        if self.trust_policy is not None:
            path = self.registry_path()
            try:
                self._registry_mtime = (str(path), path.stat().st_mtime_ns)
            except OSError:
                self._registry_mtime = (str(path), -1)
            self._reconcile_async()   # stored verdicts made under an older registry/policy
            self._reputation_auto_update()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        try:
            self.guard.warm()         # O(1) index from the persisted list + eligible stored findings
        except Exception:  # noqa: BLE001 — the Guard must never stop the server from starting
            logger.exception("Guard warm-up failed; the Guard list starts empty")
        self.heartbeats.mark("pipeline")
        await self.pipeline.start()

    async def stop(self) -> None:
        await self.pipeline.stop()
        try:
            self.guard.stop()
        except Exception:  # noqa: BLE001
            logger.exception("Guard stop failed")
        self.repo.close()

    def uptime_s(self) -> int:
        return int(time.monotonic() - self.started_at)

    def status(self) -> dict:
        beats = self.heartbeats.snapshot()
        return {
            "mode": self.mode,
            "heartbeats": {
                "crt": beats.get("crt", -1),
                "phishtank": beats.get("phishtank", -1),
                "pipeline": beats.get("pipeline", -1),
                "ai": self.settings.ai_state,
            },
            "counts": self.repo.counts(self.mode),
            "uptime_s": self.uptime_s(),
        }

    def readiness(self) -> dict:
        """Operator-facing configuration truth (no secrets)."""
        registry = self.trust_policy.registry if self.trust_policy else None
        now = datetime.now(timezone.utc)
        return {
            "app_env": self.settings.app_env,
            "mode": self.mode,
            "trust_policy_loaded": self.trust_policy is not None,
            "registry_version": registry.version if registry else None,
            "registry_trusted_entries": len(registry.trusted(now)) if registry else 0,
            "registry_total_entries": len(registry.entries) if registry else 0,
            "portal_users": self.repo.user_count(),
            "official_snapshot_dir_exists": self.settings.official_snapshot_dir.exists(),
            "local_open_access": self.settings.local_open_access,
            "registry_error": self.registry_error,
            "policy_version": POLICY_VERSION,
            "reputation": {
                **(self.trust_policy.reputation.status(now) if self.trust_policy and self.trust_policy.reputation else {"loaded": False}),
                "auto_update": self.settings.reputation_auto_update,
                "last_update_error": self.reputation_update_error,
            },
        }

    def set_mode(self, mode: str) -> dict:
        # Compatibility route, locked to live mode.
        if mode != "live":
            raise ValueError("demo mode has been removed; only live mode is supported")
        self.repo.set_meta("mode", self.mode)
        self.heartbeats.mark("pipeline")
        return {"mode": self.mode}

    def publish(self, event: str, data: dict) -> None:
        if event == "finding" and isinstance(data, dict):
            data = self.tag(data) or data  # SSE carries the same central tag as the REST API
            self.guard_offer(data, GuardManager.source_of(data))      # Radar / Sweep → Guard live loop
            source = str(data.get("source") or "")
            if source in self.repo.RESTRICTED_SOURCES:
                return  # investigation findings never go to the public stream
        self._emit(event, data)

    def _emit(self, event: str, data: dict) -> None:
        """Thread-safe SSE publish (the Guard's debounced sync runs on a timer thread)."""
        loop = self._loop
        if (threading.current_thread().name == "guard-sync" and loop is not None and loop.is_running()):
            loop.call_soon_threadsafe(self.events.publish, event, data)
            return
        self.events.publish(event, data)

    def _fresh_guard(self, response: dict) -> dict:
        """A stored Checker result reports the Guard's state NOW, not when it was stored."""
        if isinstance(response, dict) and "guard" in response and response.get("domain"):
            try:
                return {**response, "guard": self.guard.check(str(response["domain"]))}
            except Exception:  # noqa: BLE001
                return response
        return response

    def guard_offer(self, item: dict | None, source: str, finding_id: int | None = None) -> dict:
        if not item or getattr(self, "guard", None) is None:
            return {"listed": False}
        try:
            return self.guard.offer(item, source, finding_id)
        except Exception:  # noqa: BLE001 — the Guard must never break a check
            logger.exception("Guard offer failed")
            return {"listed": False, "reason": "guard error"}

    def tag_report(self, report: dict | None) -> dict | None:
        if report and isinstance(report.get("evidence"), dict) and not report["evidence"].get("tag"):
            report = {**report, "evidence": self.tag(report["evidence"])}
        return report

    # ------------------------------------------------------------- findings (tagged)

    # ------------------------------------------------------------- registry freshness

    def registry_path(self) -> Path:
        reg = self.trust_policy.registry if self.trust_policy else None
        return Path(getattr(reg, "path", None) or DEFAULT_REGISTRY_PATH)

    def maybe_reload_registry(self, force: bool = False) -> bool:
        """Approvals / revocations take effect without a restart. Checked at most every 2 s.

        An invalid registry FAILS CLOSED: an empty registry is installed (nothing authenticates,
        nothing is SAFE) until the file is fixed. → True when the registry changed."""
        if self.trust_policy is None:
            return False
        now = time.monotonic()
        if not force and now - self._registry_checked_at < 2.0:
            return False
        self._registry_checked_at = now
        self.maybe_reload_reputation()
        path = self.registry_path()
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            mtime = -1
        key = (str(path), mtime)
        if self._registry_mtime is None or self._registry_mtime[0] != key[0]:
            self._registry_mtime = key      # registry object was replaced (e.g. tests): just start watching
            if not force:
                return False
        if not force and key == self._registry_mtime:
            return False
        self._registry_mtime = key
        previous = self.trust_policy.registry.version
        synthetic = any(getattr(e, "synthetic", False) for e in self.trust_policy.registry.entries)
        try:
            registry = Registry.load(path, allow_synthetic=synthetic)
            self.registry_error = None
        except Exception as exc:  # fail closed
            logger.error("Official registry could not be loaded (%s); nothing will authenticate until fixed", exc)
            registry = Registry((), version="reg_unavailable", path=path)
            self.registry_error = str(exc)[:300]
        self.trust_policy.registry = registry
        if registry.version != previous:
            logger.info("Official registry reloaded: %s → %s", previous, registry.version)
            self._reconcile_async()
            return True
        return False

    def _reconcile_async(self) -> None:
        threading.Thread(target=self.reconcile_findings, name="reconcile-findings", daemon=True).start()

    def reconcile_findings(self) -> int:
        """Re-evaluate every stored, tagged finding decided under an older registry or policy."""
        if self.trust_policy is None:
            return 0
        changed = 0
        for finding_id in self.repo.findings_with_stale_policy(self.trust_policy.registry.version, POLICY_VERSION,
                                                               self.trust_policy.reputation_version):
            before = self.repo.get_finding(finding_id)
            after = self.tag(before)
            if before and after and before.get("tag") != after.get("tag"):
                changed += 1
        return changed

    def tag(self, finding: dict | None) -> dict | None:
        if finding is None:
            return None
        if self.trust_policy is None:
            out = dict(finding)
            out.setdefault("tag", verdicts.ui_tag(out.get("verdict", "UNKNOWN")))
            return out
        if finding.get("tag") and finding.get("id"):
            # Stored verdict: re-evaluate against the current registry/policy; persist if it changed.
            fields = self.trust_policy.retag(finding)
            if fields is not None:
                return self.repo.update_finding_policy(int(finding["id"]), fields) or {**finding, **fields}
            return finding
        return self.trust_policy.tag_finding(finding)

    def get_findings(self, limit: int, include_restricted: bool = False) -> list[dict]:
        self.maybe_reload_registry()
        rows = self.repo.get_findings(limit, self.mode, include_restricted=include_restricted)
        return [self.tag(row) for row in rows]

    def get_finding(self, finding_id: int) -> dict | None:
        self.maybe_reload_registry()
        return self.tag(self.repo.get_finding(finding_id))

    def finding_is_restricted(self, finding_id: int) -> bool:
        return (self.repo.finding_source(finding_id) or "") in self.repo.RESTRICTED_SOURCES

    def guard_rows(self) -> list[dict]:
        """C6 Guard feed = the live Guard list (same data as blocklist.txt)."""
        if getattr(self, "guard", None) is not None and self.guard.warmed:
            return self.guard.feed_rows()
        rows = self.repo.get_guard_rows(self.mode, self.settings.guard_block_misleading)
        if self.trust_policy is None:
            return rows
        registry = self.trust_policy.registry
        # A registry-listed domain is never fed to Guard, whatever its status: a compromised
        # official site is a manual-review case, not an automatic DNS block.
        return [row for row in rows if not registry.entries_for_host(str(row.get("domain", "")))]

    def guard_stats(self, origin: str = "") -> dict:
        return self.guard.stats(self.settings.guard_public_origin or origin)

    # ------------------------------------------------------------- scanning

    def scan(self, kind: str, input_value: str, lang: str, *, live: bool = False,
             portal_evidence: bool = True) -> dict:
        """`live` (Checker): RDAP age, secure page retrieval and feed lookups for up to 3 links.
        Without it (extension /api/scan) only offline checks run — no per-result outbound calls."""
        self.maybe_reload_registry()
        evidence: dict = {}
        policy = self.trust_policy

        def context_for(candidate: str) -> dict:
            ctx, ev = policy.evidence_context(candidate, live=live and len(evidence) < 3)
            if ev is not None:
                evidence[candidate] = ev
                evidence[candidate.strip()] = ev
            return ctx

        result = scorer.score_request(
            kind,
            input_value,
            lang,
            **self.catalog.scoring_kwargs(),
            thresholds=self.settings.thresholds,
            # The Checker (portal_evidence=False) never reads Portal findings / evidence.
            evidence_lookup=(lambda domain: self.repo.find_evidence_url(domain, self.mode)) if portal_evidence else None,
            context_for=context_for if policy is not None else None,
        )
        # Authenticated-domain check BEFORE any tag is returned. WS1 fields are untouched.
        if self.trust_policy is not None:
            try:
                return self.trust_policy.apply_to_scan_result(result, kind=kind, input_value=input_value,
                                                              live_evidence=evidence)
            except Exception as exc:  # fail closed
                logger.warning("Trust policy error (%s); returning non-SAFE fallback tag", type(exc).__name__)
        result["tag"] = verdicts.ui_tag(result["verdict"])  # never SAFE: UNKNOWN → WARNING
        result["manual_review"] = True
        result["domain_auth"] = None
        result["gov_verification"] = None
        result["trust_reasons"] = ["trust policy unavailable — authenticity could not be checked"]
        result["blockable"] = False
        result["policy_version"] = None
        return result

    # ------------------------------------------------------------- live Checker

    def check(self, raw: str, lang: str, request_id: str, client_ip: str) -> tuple[dict, bool]:
        """Checker → engine → trust policy → evidence → SEND to the Police Portal. → (result, new).

        Independent of the Portal: the Checker never reads Portal findings, cases, evidence or
        officer data. It keeps its OWN result store (``checker_store``): a repeated request id, or the
        same input while its stored result is still valid, returns the stored result directly —
        nothing is re-analysed and nothing is sent again.
        Raises CheckInputError (bad input), CheckFailed (analysis or sending failed).
        """
        classified = checker_lib.classify(raw)
        chash = checker_lib.content_hash(classified.input_type, classified.value)
        client = checker_lib.client_hash(client_ip or "unknown")
        repeat = self.checker_store.by_request(request_id)
        if repeat is not None:
            return self._fresh_guard(repeat), False
        self.maybe_reload_registry()
        key = None
        if self.settings.check_cache_ttl_s > 0:
            key = checker_store_lib.result_key(classified.input_type, classified.value, lang, self.check_versions())
            stored = self.checker_store.get(key)
            if stored is not None:
                self.checker_store.remember_request(request_id, stored)
                return self._fresh_guard(stored), False

        scanned_at = utc_now()
        try:
            result = self.scan(classified.input_type, classified.value, lang, live=True, portal_evidence=False)
        except Exception as exc:
            logger.exception("Checker analysis failed")
            raise CheckFailed("analysis_failed", "the analysis could not be completed; nothing was stored") from exc

        trust_ok = self.trust_policy is not None and result.get("policy_version") is not None
        normalized = result.get("normalized") or {}
        domain = (classified.domain or normalized.get("unicode_host") or normalized.get("host") or "").lower()
        if classified.input_type == checker_lib.INPUT_TEXT:
            submitted, redactions = checker_lib.redact(classified.original)
        else:
            submitted, redactions = classified.value, {}
        signals = checker_lib.redact_signals(list(result.get("signals") or []))
        checks = checker_lib.check_statuses(result, classified.input_type, trust_ok)
        scan_status = "completed" if all(c["status"] in ("completed", "not_applicable") for c in checks) else "partial"
        detail = {
            "source": "checker",
            "input_type": classified.input_type,
            "submitted_input": submitted,
            "normalized_url": classified.normalized_url,
            "analyzed_url": result.get("analyzed_url"),
            "urls": result.get("urls") or [],
            "registrable_domain": normalized.get("registrable_domain"),
            "normalized": normalized or None,
            "homograph": result.get("homograph"),
            "tag": result.get("tag"),
            "manual_review": result.get("manual_review"),
            "domain_auth": result.get("domain_auth"),
            "gov_verification": result.get("gov_verification"),
            "trust_reasons": result.get("trust_reasons") or [],
            "maliciousness": result.get("maliciousness"),
            "policy_version": result.get("policy_version"),
            "reputation_version": result.get("reputation_version"),
            "reason_codes": result.get("reason_codes") or [],
            "final_domain_auth": result.get("final_domain_auth"),
            "evidence": result.get("evidence") or [],
            "live_evidence": result.get("live_evidence"),
            "scam_type": result.get("scam_type"),
            "signals": signals,
            "risk_score": result.get("score"),
            "scanned_at": scanned_at,
            "scan_status": scan_status,
            "checks": checks,
            "precautions": checker_lib.precautions(str(result.get("tag")), signals, classified.input_type,
                                                   result.get("domain_auth")),
            "redactions": redactions,
            "engine_version": scorer.ENGINE_VERSION,
        }
        reasons = [checker_lib.redact(str(r))[0] for r in result.get("reasons") or []]
        try:
            # SEND to the Police Portal (write only — nothing is read back from it).
            finding_id, created = self.repo.insert_check_finding(
                request_id=request_id,
                content_hash=chash,
                client_hash=client,
                domain=domain,
                score=float(result.get("score") or 0.0),
                verdict=str(result.get("verdict") or "UNKNOWN"),
                reasons=reasons,
                l1_detail={str(s["name"]): float(s.get("weight") or 0) for s in signals},
                detail=detail,
                created_at=scanned_at,
            )
        except Exception as exc:
            logger.exception("Checker finding could not be sent to the Police Portal")
            unsaved = {**detail, "id": None, "verdict": result.get("verdict"), "score": result.get("score"),
                       "reasons": result.get("reasons"), "domain": domain}
            raise CheckFailed("persist_failed", "the analysis finished but could not be saved to the Police Portal",
                              unsaved) from exc
        # The response is built from the Checker's own analysis — the same record that was sent.
        response = finding_with_detail({"id": finding_id, "domain": domain, "verdict": result.get("verdict"),
                                        "score": result.get("score"), "reasons": reasons, "source": "checker",
                                        "first_seen": scanned_at, "cert_issued": scanned_at},
                                       {**detail, "created_at": scanned_at})
        if classified.input_type == checker_lib.INPUT_URL:
            self.guard_offer({**response, "input_type": "url"}, "checker", finding_id)
        response["guard"] = self.guard.check(domain) if domain else None
        incomplete = any(str(r.get("status")) in ("unavailable", "timeout", "no_data", "stale", "LIST_STALE",
                                                  "LIST_MISSING", "LIST_INVALID")
                         for r in detail.get("evidence") or []) or scan_status != "completed"
        ttl = self.settings.check_cache_partial_ttl_s if incomplete else self.settings.check_cache_ttl_s
        try:
            self.checker_store.put(key if self.settings.check_cache_ttl_s > 0 else None, request_id, response,
                                   min(ttl, self.settings.check_cache_ttl_s))
        except Exception:  # noqa: BLE001 — the store is an optimisation; the check itself succeeded
            logger.warning("Checker result store unavailable; result returned without storing a copy")
        return response, created

    @property
    def checker_store(self) -> checker_store_lib.CheckerStore:
        if self._checker_store is None:
            with self._checker_store_lock:
                if self._checker_store is None:
                    store = checker_store_lib.CheckerStore(self.settings.checker_store_path)
                    # Results stored by an older build (code / rules / registry files) are dropped.
                    store.reset_if_build_changed(build_fingerprint())
                    self._checker_store = store
        return self._checker_store

    def check_versions(self) -> dict:
        """Everything a stored Checker result depends on. Any change → the stored result is not reused."""
        tp = self.trust_policy
        return {"engine": scorer.ENGINE_VERSION, "policy": POLICY_VERSION, "build": build_fingerprint(),
                "registry": tp.registry.version if tp else None,
                "reputation": tp.reputation_version if tp else None}

    def input_type_of(self, finding: dict) -> str:
        if finding.get("input_type"):
            return str(finding["input_type"])
        source = str(finding.get("source") or "")
        return "url" if source.startswith(("investigation", "sweep")) else "domain"

    def portal_findings(
        self,
        *,
        q: str | None = None,
        tag: str | None = None,
        input_type: str | None = None,
        source: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        rows = [self.tag(row) for row in self.repo.search_findings(
            q=(q or "").strip() or None, source=source, date_from=date_from, date_to=date_to)]
        facets = {"tag": {}, "input_type": {}}
        for row in rows:
            row["input_type"] = self.input_type_of(row)
            facets["tag"][row["tag"]] = facets["tag"].get(row["tag"], 0) + 1
            facets["input_type"][row["input_type"]] = facets["input_type"].get(row["input_type"], 0) + 1
        if tag:
            rows = [row for row in rows if row.get("tag") == tag]
        if input_type:
            rows = [row for row in rows if row.get("input_type") == input_type]
        return {"total": len(rows), "offset": offset, "limit": limit,
                "findings": rows[offset:offset + limit], "facets": facets}

    def investigate(self, url: str, text: str | None, investigator: str) -> dict:
        """Portal investigation: scan + verify + PERSIST as a restricted finding."""
        if self.trust_policy is None:
            raise HTTPException(status_code=503, detail="trust policy unavailable; investigation refused")
        normalized, problem = channel_urls.normalize_result_url(url)
        if not normalized:
            raise HTTPException(status_code=422, detail=f"invalid URL: {problem}")
        self.maybe_reload_registry()
        assessed = self.trust_policy.assess_url(normalized, text=text or None, live=True)
        host = assessed.get("host") or assessed.get("registrable_domain") or ""
        if not host:
            raise HTTPException(status_code=422, detail="URL has no host")
        now = utc_now()
        detail = {
            "source": "investigation",
            "tag": assessed["tag"],
            "manual_review": assessed["manual_review"],
            "domain_auth": assessed["domain_auth"],
            "gov_verification": assessed["gov_verification"],
            "trust_reasons": assessed["trust_reasons"],
            "maliciousness": assessed.get("maliciousness"),
            "scam_type": assessed["scam_type"],
            "signals": assessed["signals"],
            "submitted_url": normalized,
            "investigator": investigator,
            "policy_version": assessed["policy_version"],
            "reputation_version": assessed.get("reputation_version"),
            "reason_codes": assessed.get("reason_codes") or [],
            "final_domain_auth": assessed.get("final_domain_auth"),
            "evidence": assessed.get("evidence") or [],
            "live_evidence": assessed.get("live_evidence"),
            "registrable_domain": assessed["registrable_domain"],
        }
        finding = self.repo.insert_finding(
            domain=host,
            score=assessed["score"],
            verdict=assessed["verdict"],
            reasons=assessed["reasons"],
            l1_detail={s["name"]: s["weight"] for s in assessed["signals"]},
            source="investigation",
            first_seen=now,
            created_at=now,
            detail=detail,
        )
        tagged = self.tag(finding) or finding
        self.guard_offer({**tagged, "input_type": "url"}, "investigation", int(tagged.get("id") or 0) or None)
        return tagged

    def record_sweep_finding(self, row: dict, channel: str) -> int | None:
        """Sweep rows tagged FAKE/MISLEADING become findings (domain + evidence only)."""
        if row.get("tag") not in ("FAKE", "MISLEADING"):
            return None
        url = str(row.get("url") or "")
        if not url.startswith(("http://", "https://")):
            return None
        host = urlsplit(url).hostname or ""
        if not host:
            return None
        now = utc_now()
        finding = self.repo.insert_finding(
            domain=host,
            score=float(row.get("score") or 0.0),
            verdict=str(row.get("verdict") or "UNKNOWN"),
            reasons=list(row.get("reasons") or []),
            source=f"sweep:{channel}",
            first_seen=now,
            created_at=now,
            detail={k: row.get(k) for k in ("tag", "manual_review", "domain_auth", "gov_verification",
                                             "trust_reasons")} | {"source": f"sweep:{channel}"},
        )
        self.publish("finding", self.tag(finding) or finding)
        return int(finding["id"])

    def ensure_evidence(self, finding_id: int) -> Path | None:
        # Real evidence only. A missing render is a 404, never a generated stand-in.
        return self.repo.ensure_evidence_file(finding_id)

    async def event_stream(self, is_disconnected: Callable):
        queue = self.events.subscribe()
        try:
            yield sse("heartbeat", self.status())
            while not await is_disconnected():
                try:
                    message = await asyncio.wait_for(
                        queue.get(),
                        timeout=self.settings.heartbeat_interval_s,
                    )
                except asyncio.TimeoutError:
                    message = {"event": "heartbeat", "data": self.status()}
                yield sse(message["event"], message["data"])
        finally:
            self.events.unsubscribe(queue)


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware: security headers on every HTTP response."""

    def __init__(self, app, headers: dict[str, str]) -> None:
        self.app = app
        self.headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {name for name, _ in message.get("headers", [])}
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + [
                    (name, value) for name, value in self.headers if name not in existing
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


ROUTERS = (auth, system, examples, check_api, findings, scan, health, stream, investigations, reports, ai_api, sweep, guard)


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = Runtime(settings)
    active_settings = runtime.settings
    _install_access_log_filter()
    active_settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    active_settings.gallery_dir.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runtime.start()
        yield
        await runtime.stop()

    docs = {} if not active_settings.is_production else {"docs_url": None, "redoc_url": None, "openapi_url": None}
    app = FastAPI(
        **docs,
        title="Daggers API",
        version="2.0.0",
        description="Integrated Daggers: intelligence engine, official-source verification, channels, "
        "Guard, Police Portal, AI Analyst. Unofficial prototype — not an Abu Dhabi Police system.",
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    if active_settings.cors_origins:
        # Public, credential-less endpoints only (extension / static mirrors). The portal is
        # same-origin and uses SameSite=Strict cookies, so CORS never carries credentials.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=active_settings.cors_origins,
            allow_origin_regex=active_settings.cors_origin_regex,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Accept", "X-Requested-With", "If-None-Match"],
            expose_headers=["ETag", "X-Guard-Entries", "Retry-After"],
        )
    app.add_middleware(SecurityHeadersMiddleware, headers=security.security_headers(active_settings.is_production))

    for module in ROUTERS:
        app.include_router(module.router)

    app.mount(
        "/evidence",
        StaticFiles(directory=str(active_settings.evidence_dir), check_dir=False),
        name="evidence",
    )

    if active_settings.web_dir.exists():
        app.mount("/", StaticFiles(directory=str(active_settings.web_dir), html=True), name="web")
    else:

        async def root() -> dict:
            return {"name": "Daggers", "status": "/api/status", "docs": "/docs"}

        app.add_api_route("/", root, methods=["GET"], include_in_schema=False)

    return app


app = create_app()
