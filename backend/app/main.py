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
from fastapi.staticfiles import StaticFiles

from .api import findings, health, scan, stream
from .catalog import load_catalogs
from .config import Heartbeats, Settings
from .core import scorer
from .db.repo import Repository
from .radar.pipeline import RadarPipeline
from .reports.queue import ReportQueue
from .vision import diff

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
        self.mode = self.settings.mode
        self.optional_routers: dict[str, str] = {}
        self.report_queue = ReportQueue(self.repo, clone_min=self.settings.autofile_clone_min)
        self.pipeline = RadarPipeline(
            repo=self.repo,
            settings=self.settings,
            catalog=self.catalog,
            report_queue=self.report_queue,
            publish=self.publish,
            heartbeats=self.heartbeats,
            mode_getter=lambda: self.mode,
            status_getter=self.status,
        )

    async def start(self) -> None:
        missing = self.repo.initialize()
        if missing or not self.repo.get_meta("seeded_at"):
            self.repo.seed()
        else:
            self.repo.ensure_assets()
        self.mode = self.settings.mode
        self.repo.set_meta("mode", self.mode)
        self.heartbeats.mark("pipeline")
        await self.pipeline.start()

    async def stop(self) -> None:
        await self.pipeline.stop()
        self.repo.close()

    def uptime_s(self) -> int:
        return int(time.monotonic() - self.started_at)

    def status(self) -> dict:
        beats = self.heartbeats.snapshot()
        ai_router = self.optional_routers.get("backend.app.api.ai") == "mounted"
        ai_state = "ok" if self.settings.ai_state == "ok" or ai_router else self.settings.ai_state
        return {
            "mode": self.mode,
            "heartbeats": {
                "crt": beats.get("crt", -1),
                "phishtank": beats.get("phishtank", -1),
                "pipeline": beats.get("pipeline", -1),
                "ai": ai_state,
            },
            "counts": self.repo.counts(self.mode),
            "uptime_s": self.uptime_s(),
        }

    def set_mode(self, mode: str) -> dict:
        if mode not in {"live", "demo"}:
            raise ValueError("mode must be live or demo")
        self.mode = mode
        self.repo.set_meta("mode", mode)
        self.heartbeats.mark("pipeline")
        return {"mode": self.mode}

    def publish(self, event: str, data: dict) -> None:
        self.events.publish(event, data)

    def get_findings(self, limit: int) -> list[dict]:
        return self.repo.get_findings(limit, self.mode)

    def get_finding(self, finding_id: int) -> dict | None:
        return self.repo.get_finding(finding_id, self.mode)

    def guard_rows(self) -> list[dict]:
        return self.repo.get_guard_rows(self.mode, self.settings.guard_block_misleading)

    def guard_stats(self) -> dict:
        return self.repo.guard_stats(self.mode, self.settings.guard_block_misleading)

    def scan(self, kind: str, input_value: str, lang: str) -> dict:
        return scorer.score_request(
            kind,
            input_value,
            lang,
            **self.catalog.scoring_kwargs(),
            thresholds=self.settings.thresholds,
            evidence_lookup=lambda domain: self.repo.find_evidence_url(domain, self.mode),
        )

    def ensure_evidence(self, finding_id: int) -> Path | None:
        path = self.repo.ensure_evidence_file(finding_id, self.mode)
        if path is not None:
            return path
        finding = self.repo.get_finding(finding_id, self.mode)
        if finding is None:
            return None
        return diff.ensure_evidence_image(
            finding,
            self.settings.evidence_dir / f"{finding_id}.jpg",
            self.settings.gallery_dir,
        )

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
    """WS2/WS3 can land later; missing or broken optional routers never break WS1."""
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
        description="WS1: deterministic scam verdicts, radar, evidence, reports, and SSE.",
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

    # Optional lanes first: if WS2 later owns /api/guard/feed, its route wins.
    mount_optional_routers(app, runtime)
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
                "message": "Workstream 1 is online; WS2/WS3 static UI is not present in this checkout.",
            }

        app.add_api_route("/", root, methods=["GET"], include_in_schema=False)

    return app


app = create_app()
