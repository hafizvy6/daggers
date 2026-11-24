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


def _canonical_ai_state(env: Mapping[str, str]) -> str:
    """One production AI state, with backward-compatible legacy switches."""
    provider = (env.get("AI_PROVIDER", "auto") or "auto").strip().lower()
    if env.get("AI_ON", "1") == "0" or provider == "template":
        return "template"
    raw = env.get("AI_STATE")
    if raw is None:
        # Supplying a key is an explicit opt-in to the live adapter.
        return "live" if (env.get("GEMINI_KEY") or env.get("GROQ_KEY")) else "template"
    return {
        "off": "off",
        "template": "template",
        "live": "live",
        "on": "live",
        "auto": "live",
        "ok": "live",
    }.get(raw.strip().lower(), "template")


def _guard_hostname(env: Mapping[str, str]) -> str:
    explicit = (env.get("NEXTDNS_DNS_HOSTNAME") or "").strip().lower()
    if explicit:
        return explicit
    profile = (env.get("NEXTDNS_PROFILE") or "").strip().lower()
    if profile and profile.isalnum() and 4 <= len(profile) <= 12:
        return f"{profile}.dns.nextdns.io"
    return ""


@dataclass(frozen=True)
class Settings:
    """Environment-driven production configuration.

    Daggers has one runtime mode: live. With no external adapters configured it
    is still live, but it honestly reports empty feeds and unconfigured sources.
    """

    project_root: Path = ROOT
    backend_dir: Path = BACKEND_DIR
    db_path: Path = BACKEND_DIR / "data" / "daggers.db"
    evidence_dir: Path = BACKEND_DIR / "data" / "evidence"
    gallery_dir: Path = BACKEND_DIR / "data" / "gallery"
    web_dir: Path = ROOT / "web"

    mode: str = "live"
    environment: str = "production"
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
    search_live_enabled: bool = False
    maps_live_enabled: bool = False
    sweep_allow_arbitrary: bool = False
    sweep_rate_per_min: int = 6
    sweep_max_concurrent: int = 2
    guard_max_age_days: int = 30

    http_timeout_s: float = 10.0
    render_timeout_ms: int = 15000
    http_user_agent: str = "Daggers-Research/1.0"

    serper_api_key: str = ""
    google_places_api_key: str = ""
    phishtank_key: str = ""
    gemini_key: str = ""
    groq_key: str = ""
    nextdns_api_key: str = ""
    nextdns_profile: str = ""
    guard_dns_hostname: str = ""

    crt_poll_interval_s: int = 60
    feed_poll_interval_s: int = 120
    pipeline_poll_interval_s: int = 4
    heartbeat_interval_s: int = 5
    crt_min_query_gap_s: int = 20
    ai_state: str = "template"  # off | template | live
    ai_provider: str = "auto"    # legacy/optional override: auto | gemini | groq | template
    ai_on: bool = True
    ai_debug: bool = False
    gemini_model: str = "gemini-2.0-flash"
    groq_model: str = "llama-3.3-70b-versatile"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = env if env is not None else os.environ
        return cls(
            db_path=_path("DB_PATH", BACKEND_DIR / "data" / "daggers.db", env),
            evidence_dir=_path("EVIDENCE_DIR", BACKEND_DIR / "data" / "evidence", env),
            gallery_dir=_path("GALLERY_DIR", BACKEND_DIR / "data" / "gallery", env),
            web_dir=_path("WEB_DIR", ROOT / "web", env),
            mode="live",
            environment=env.get("APP_ENV", "production").strip().lower() or "production",
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
            search_live_enabled=_bool("SEARCH_LIVE_ENABLED", False, env),
            maps_live_enabled=_bool("MAPS_LIVE_ENABLED", False, env),
            sweep_allow_arbitrary=_bool("SWEEP_ALLOW_ARBITRARY", False, env),
            sweep_rate_per_min=max(1, _int("SWEEP_RATE_PER_MIN", 6, env)),
            sweep_max_concurrent=max(1, _int("SWEEP_MAX_CONCURRENT", 2, env)),
            guard_max_age_days=max(1, _int("GUARD_MAX_AGE_DAYS", 30, env)),
            http_timeout_s=_float("HTTP_TIMEOUT_S", 10.0, env),
            render_timeout_ms=_int("RENDER_TIMEOUT_MS", 15000, env),
            http_user_agent=env.get("HTTP_USER_AGENT", "Daggers-Research/1.0"),
            serper_api_key=env.get("SERPER_API_KEY", ""),
            google_places_api_key=env.get("GOOGLE_PLACES_API_KEY", ""),
            phishtank_key=env.get("PHISHTANK_KEY", ""),
            gemini_key=env.get("GEMINI_KEY", ""),
            groq_key=env.get("GROQ_KEY", ""),
            nextdns_api_key=env.get("NEXTDNS_API_KEY", ""),
            nextdns_profile=env.get("NEXTDNS_PROFILE", ""),
            guard_dns_hostname=_guard_hostname(env),
            crt_poll_interval_s=max(20, _int("CRT_POLL_INTERVAL_S", 60, env)),
            feed_poll_interval_s=max(20, _int("FEED_POLL_INTERVAL_S", 120, env)),
            pipeline_poll_interval_s=max(1, _int("PIPELINE_POLL_INTERVAL_S", 4, env)),
            heartbeat_interval_s=max(1, _int("HEARTBEAT_INTERVAL_S", 5, env)),
            crt_min_query_gap_s=max(20, _int("CRT_MIN_QUERY_GAP_S", 20, env)),
            ai_state=_canonical_ai_state(env),
            ai_provider=(env.get("AI_PROVIDER", "auto") or "auto").strip().lower(),
            ai_on=_bool("AI_ON", True, env),
            ai_debug=_bool("AI_DEBUG", False, env),
            gemini_model=env.get("GEMINI_MODEL", "gemini-2.0-flash"),
            groq_model=env.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        )

    @property
    def thresholds(self) -> dict[str, float]:
        return {
            "MALICIOUS": self.malicious_threshold,
            "SUSPICIOUS": self.suspicious_threshold,
            "RENDER_SCORE_MIN": self.render_score_min,
            "AUTOFILE_CLONE_MIN": self.autofile_clone_min,
        }

    def adapter_status(self) -> dict[str, dict[str, bool | str]]:
        """Public readiness flags only — never expose secret values."""
        return {
            "crt": {"enabled": self.crt_enabled, "configured": True},
            "feeds": {
                "enabled": self.feeds_enabled,
                "configured": bool(self.phishtank_key),
                "fallback_sources": True,
            },
            "enrich": {"enabled": self.enrich_enabled, "configured": True},
            "render": {"enabled": self.render_enabled, "configured": True},
            "search": {
                "enabled": self.search_live_enabled,
                "configured": bool(self.serper_api_key),
                "fallback_source": True,
            },
            "maps": {
                "enabled": self.maps_live_enabled,
                "configured": bool(self.google_places_api_key),
            },
            "ai": {
                "enabled": self.ai_state == "live",
                "configured": bool(self.gemini_key or self.groq_key),
                "state": self.ai_state,
                "template_fallback": True,
            },
            "guard": {
                "enabled": True,
                "configured": bool(self.nextdns_api_key and self.nextdns_profile),
                "hostname": self.guard_dns_hostname,
                "manual_sync": True,
            },
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
