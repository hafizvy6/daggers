from __future__ import annotations

import asyncio
import importlib
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import examples, findings, health, scan, stream
from .catalog import load_catalogs
from .config import Heartbeats, Settings
from .core import scorer, verdicts
from .db.repo import Repository
from .radar.enrich import parse_age_hours
from .radar.pipeline import RadarPipeline
from .reports.intake import PoliceIntakeClient
from .reports.queue import ReportQueue

logger = logging.getLogger("daggers.app")

OPTIONAL_ROUTER_MODULES = (
    "backend.app.api.sweep",
    "backend.app.api.guard",
    "backend.app.api.reports",
    "backend.app.api.ai",
)


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
    """Application state shared by every route; routes contain no business logic."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self.started_at = time.monotonic()
        self.repo = Repository(self.settings)
        self.catalog = load_catalogs()
        self.heartbeats = Heartbeats()
        self.events = EventBus()
        self.mode = "live"
        self.optional_routers: dict[str, str] = {}
        self.report_queue = ReportQueue(
            self.repo,
            clone_min=self.settings.autofile_clone_min,
            auto_report_enabled=self.settings.auto_report_enabled,
            intake=PoliceIntakeClient(self.settings),
        )
        self.pipeline = RadarPipeline(
            repo=self.repo,
            settings=self.settings,
            catalog=self.catalog,
            report_queue=self.report_queue,
            publish=self.publish,
            heartbeats=self.heartbeats,
            status_getter=self.status,
        )

    async def start(self) -> None:
        # Boot creates the canonical schema only. It never inserts product data.
        self.repo.initialize()
        self.repo.set_meta("mode", self.mode)
        self.repo.set_meta("schema_version", "1")
        self._reconcile_finding_verdicts()
        self._backfill_automatic_dossiers()
        self.heartbeats.mark("pipeline")
        await self.pipeline.start()

    def _reconcile_finding_verdicts(self) -> None:
        """Bring historical verdicts in line with the current evidence rules.

        This recalculates already-stored radar findings without network calls. A
        finding downgraded below its previous verdict has its old composed
        evidence invalidated because that image embedded the superseded claim.
        """
        changed = 0
        for row in self.repo.list_findings_for_reconciliation(limit=5000):
            l1 = row.get("l1_detail") or {}
            context = {
                "cert_age_hours": parse_age_hours(row.get("cert_issued")),
                "clone_score": float(row.get("clone") or 0),
                "phishtank_confirmed": "feeds.phishtank_confirmed" in l1,
                "form_action_mismatch": "content.form_action_mismatch" in l1,
                "payment_harvest_fields": "content.payment_harvest_fields" in l1,
                "obfuscated_script": "content.obfuscated_script" in l1,
            }
            result = scorer.score_url(
                f"https://{row['domain']}/",
                brands=list(self.catalog.brands),
                lures={key: list(value) for key, value in self.catalog.lures.items()},
                context=context,
                suffix_resolver=self.catalog.suffix_resolver,
                text=str(row["domain"]),
                thresholds=self.settings.thresholds,
            )
            old_verdict = str(row.get("verdict") or "UNKNOWN").upper()
            new_verdict = str(result.verdict).upper()
            reasons_changed = list(row.get("reasons") or []) != list(result.reasons)
            if old_verdict == new_verdict and abs(float(row.get("score") or 0) - result.score) < 0.0001 and not reasons_changed:
                continue
            old_rank = verdicts.RANK.get(old_verdict, 0)
            new_rank = verdicts.RANK.get(new_verdict, 0)
            self.repo.update_finding_analysis(
                int(row["id"]),
                score=result.score,
                verdict=new_verdict,
                reasons=result.reasons,
                l1_detail=result.l1_detail,
                clone_score=context["clone_score"],
                rendered=False if new_rank < old_rank else None,
            )
            if new_rank < old_rank:
                self.repo.clear_evidence(int(row["id"]))
            changed += 1
        if changed:
            logger.info("reconciled %s historical radar verdict(s)", changed)

    def _backfill_automatic_dossiers(self) -> None:
        """Create portal dossiers for pre-existing actionable findings once."""
        created = 0
        for row in self.repo.list_findings_for_reconciliation(limit=5000):
            if str(row.get("verdict") or "UNKNOWN").upper() not in {"SUSPICIOUS", "MISLEADING", "MALICIOUS"}:
                continue
            if self.repo.report_exists(int(row["id"])):
                continue
            contract = self.repo.get_finding(int(row["id"]))
            if not contract:
                continue
            report = self.report_queue.maybe_auto_file(contract)
            created += 1 if report else 0
        if created:
            logger.info("backfilled %s automatic police-portal dossier(s)", created)

    async def stop(self) -> None:
        await self.pipeline.stop()
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
            "counts": self.repo.counts(),
            "uptime_s": self.uptime_s(),
        }

    def adapter_status(self) -> dict:
        return self.settings.adapter_status()

    def set_mode(self, mode: str) -> dict:
        # Compatibility route, locked to live mode.
        if mode != "live":
            raise ValueError("demo mode has been removed; only live mode is supported")
        self.repo.set_meta("mode", self.mode)
        self.heartbeats.mark("pipeline")
        return {"mode": self.mode}

    def publish(self, event: str, data: dict) -> None:
        self.events.publish(event, data)

    def get_findings(
        self,
        limit: int,
        *,
        min_score: float | None = None,
        include_unknown: bool = False,
        include_suppressed: bool = False,
    ) -> list[dict]:
        return self.repo.get_findings(
            limit,
            min_score=min_score,
            include_unknown=include_unknown,
            include_suppressed=include_suppressed,
        )

    def get_finding(self, finding_id: int) -> dict | None:
        finding = self.repo.get_finding(finding_id)
        if finding:
            finding["analyst_label"] = self.repo.get_analyst_label(str(finding["domain"]))
        return finding

    def set_finding_label(self, finding_id: int, label: str) -> dict | None:
        finding = self.repo.get_finding(finding_id)
        if finding is None:
            return None
        return self.repo.set_analyst_label(str(finding["domain"]), label)

    def get_finding_label(self, finding_id: int) -> dict | None:
        finding = self.repo.get_finding(finding_id)
        if finding is None:
            return None
        return self.repo.get_analyst_label(str(finding["domain"]))

    def analyst_label_stats(self) -> dict[str, int]:
        return self.repo.analyst_label_stats()

    def guard_rows(self) -> list[dict]:
        return self.repo.get_guard_rows(self.settings.guard_block_misleading)

    def guard_stats(self) -> dict:
        return self.repo.guard_stats(self.settings.guard_block_misleading)

    def scan(self, kind: str, input_value: str, lang: str) -> dict:
        return scorer.score_request(
            kind,
            input_value,
            lang,
            **self.catalog.scoring_kwargs(),
            thresholds=self.settings.thresholds,
            evidence_lookup=self.repo.find_evidence_url,
        )

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


def mount_optional_routers(app: FastAPI, runtime: Runtime) -> None:
    """Integration routers; a broken optional router never breaks the brain."""
    for module_name in OPTIONAL_ROUTER_MODULES:
        try:
            module = importlib.import_module(module_name)
            router = getattr(module, "router", None)
            if router is None:
                raise AttributeError("router")
            app.include_router(router)
            runtime.optional_routers[module_name] = "mounted"
        except Exception as exc:
            runtime.optional_routers[module_name] = f"skipped:{type(exc).__name__}"
            logger.info("Optional router %s not mounted (%s)", module_name, type(exc).__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = Runtime(settings)
    active_settings = runtime.settings
    active_settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    active_settings.gallery_dir.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runtime.start()
        yield
        await runtime.stop()

    app = FastAPI(
        title="Daggers Brain API",
        version="1.0.0",
        description="Live deterministic scam verdicts, radar, evidence, reports, and SSE.",
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    if active_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=active_settings.cors_origins,
            allow_origin_regex=active_settings.cors_origin_regex,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Accept", "X-Requested-With"],
        )

    # Optional routers first: if an integration router also serves /api/guard/feed, its route wins.
    mount_optional_routers(app, runtime)
    app.include_router(examples.router)
    app.include_router(findings.router)
    app.include_router(scan.router)
    app.include_router(health.router)
    app.include_router(stream.router)

    app.mount(
        "/evidence",
        StaticFiles(directory=str(active_settings.evidence_dir), check_dir=False),
        name="evidence",
    )

    if active_settings.web_dir.exists():
        @app.get("/share", include_in_schema=False)
        async def share_target() -> FileResponse:
            """PWA share_target landing; web/js/app.js routes this to #/check."""
            return FileResponse(active_settings.web_dir / "index.html")

        app.mount(
            "/",
            StaticFiles(directory=str(active_settings.web_dir), html=True),
            name="web",
        )
    else:
        async def root() -> dict:
            return {
                "name": "Daggers Brain",
                "status": "/api/status",
                "docs": "/docs",
                "message": "Live API is online; static PWA directory is not present in this checkout.",
            }

        app.add_api_route("/", root, methods=["GET"], include_in_schema=False)

    return app


app = create_app()
