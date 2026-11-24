from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"


def _bool(name: str, default: bool, env: Mapping[str, str]) -> bool:
    value = env.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float(name: str, default: float, env: Mapping[str, str]) -> float:
    try:
        return float(env.get(name, default))
    except (TypeError, ValueError):
        return default


def _int(name: str, default: int, env: Mapping[str, str]) -> int:
    try:
        return int(env.get(name, default))
    except (TypeError, ValueError):
        return default


def _path(name: str, default: Path, env: Mapping[str, str]) -> Path:
    value = env.get(name)
    if not value:
        return default
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def _csv(name: str, default: str, env: Mapping[str, str]) -> list[str]:
    raw = env.get(name, default)
    return [part.strip() for part in raw.split(",") if part.strip()]


@dataclass(frozen=True)
class Settings:
    """Environment-driven configuration. Runtime mode itself is mutable via /api/mode."""

    project_root: Path = ROOT
    backend_dir: Path = BACKEND_DIR
    db_path: Path = BACKEND_DIR / "data" / "daggers.db"
    evidence_dir: Path = BACKEND_DIR / "data" / "evidence"
    gallery_dir: Path = BACKEND_DIR / "data" / "gallery"
    seed_dir: Path = BACKEND_DIR / "seed"
    web_dir: Path = ROOT / "web"

    mode: str = "demo"
    environment: str = "dev"
    demo_mode: bool = True
    port: int = 8000

    cors_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://localhost:8000",
            "https://127.0.0.1:8000",
        ]
    )
    cors_origin_regex: str | None = None

    malicious_threshold: float = 0.65
    suspicious_threshold: float = 0.35
    render_score_min: float = 0.45
    autofile_clone_min: float = 90.0
    guard_block_misleading: bool = False

    render_enabled: bool = False
    crt_enabled: bool = False
    feeds_enabled: bool = False
    enrich_enabled: bool = False
    http_timeout_s: float = 10.0
    render_timeout_ms: int = 15000
    http_user_agent: str = "Daggers-Research/1.0"

    crt_poll_interval_s: int = 60
    feed_poll_interval_s: int = 120
    pipeline_poll_interval_s: int = 4
    heartbeat_interval_s: int = 5
    crt_min_query_gap_s: int = 20
    ai_state: str = "template"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = env if env is not None else os.environ
        demo_flag = _bool("DEMO_MODE", False, env)
        raw_mode = env.get("MODE", "demo").strip().lower()
        environment = raw_mode if raw_mode in {"dev", "demo", "venue"} else "dev"
        if demo_flag or raw_mode == "demo":
            mode = "demo"
        elif raw_mode in {"live", "venue", "dev"}:
            mode = "live"
        else:
            mode = "demo"

        return cls(
            db_path=_path("DB_PATH", BACKEND_DIR / "data" / "daggers.db", env),
            evidence_dir=_path("EVIDENCE_DIR", BACKEND_DIR / "data" / "evidence", env),
            gallery_dir=_path("GALLERY_DIR", BACKEND_DIR / "data" / "gallery", env),
            seed_dir=_path("SEED_DIR", BACKEND_DIR / "seed", env),
            web_dir=_path("WEB_DIR", ROOT / "web", env),
            mode=mode,
            environment=environment,
            demo_mode=demo_flag or mode == "demo",
            port=_int("PORT", 8000, env),
            cors_origins=_csv(
                "CORS_ORIGINS",
                "http://localhost:8000,http://127.0.0.1:8000,https://localhost:8000,https://127.0.0.1:8000",
                env,
            ),
            cors_origin_regex=env.get("CORS_ORIGIN_REGEX") or None,
            malicious_threshold=_float("MALICIOUS_THRESHOLD", 0.65, env),
            suspicious_threshold=_float("SUSPICIOUS_THRESHOLD", 0.35, env),
            render_score_min=_float("RENDER_SCORE_MIN", 0.45, env),
            autofile_clone_min=_float("AUTOFILE_CLONE_MIN", 90.0, env),
            guard_block_misleading=_bool("GUARD_BLOCK_MISLEADING", False, env),
            render_enabled=_bool("RENDER_ENABLED", False, env),
            crt_enabled=_bool("CRT_ENABLED", False, env),
            feeds_enabled=_bool("FEEDS_ENABLED", False, env),
            enrich_enabled=_bool("ENRICH_ENABLED", False, env),
            http_timeout_s=_float("HTTP_TIMEOUT_S", 10.0, env),
            render_timeout_ms=_int("RENDER_TIMEOUT_MS", 15000, env),
            http_user_agent=env.get("HTTP_USER_AGENT", "Daggers-Research/1.0"),
            crt_poll_interval_s=max(20, _int("CRT_POLL_INTERVAL_S", 60, env)),
            feed_poll_interval_s=max(20, _int("FEED_POLL_INTERVAL_S", 120, env)),
            pipeline_poll_interval_s=max(1, _int("PIPELINE_POLL_INTERVAL_S", 4, env)),
            heartbeat_interval_s=max(1, _int("HEARTBEAT_INTERVAL_S", 5, env)),
            crt_min_query_gap_s=max(20, _int("CRT_MIN_QUERY_GAP_S", 20, env)),
            ai_state=env.get("AI_STATE", "template"),
        )

    @property
    def thresholds(self) -> dict[str, float]:
        return {
            "MALICIOUS": self.malicious_threshold,
            "SUSPICIOUS": self.suspicious_threshold,
            "RENDER_SCORE_MIN": self.render_score_min,
            "AUTOFILE_CLONE_MIN": self.autofile_clone_min,
        }


class Heartbeats:
    """Real monotonic heartbeat timestamps; values reported as seconds since last beat."""

    def __init__(self) -> None:
        self._last: dict[str, float] = {}

    def mark(self, name: str) -> None:
        self._last[name] = time.monotonic()

    def seconds_since(self, name: str) -> int:
        last = self._last.get(name)
        if last is None:
            return -1
        return int(time.monotonic() - last)

    def snapshot(self) -> dict[str, int]:
        return {name: self.seconds_since(name) for name in ("crt", "phishtank", "pipeline")}
