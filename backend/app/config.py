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


def _guard_hostname(env: Mapping[str, str]) -> str:
    """The DoT hostname phones use. GUARD_DOT_HOSTNAME / NEXTDNS_DNS_HOSTNAME if set, else
    <profile>.dns.nextdns.io when a NextDNS profile id is set, else empty ("not configured")."""
    explicit = (env.get("GUARD_DOT_HOSTNAME") or env.get("NEXTDNS_DNS_HOSTNAME") or "").strip().lower()
    if explicit:
        return explicit
    profile = (env.get("NEXTDNS_PROFILE_ID") or env.get("NEXTDNS_PROFILE") or "").strip().lower()
    if profile and profile.isalnum() and 4 <= len(profile) <= 12:
        return f"{profile}.dns.nextdns.io"
    return ""


@dataclass(frozen=True)
class Settings:
    """Environment-driven configuration.

    Daggers has ONE runtime mode: live. There is no demo mode, no seed data and no
    fixture fallback; with no external adapters configured the app is still live and
    honestly reports empty feeds and unconfigured sources.
    """

    project_root: Path = ROOT
    backend_dir: Path = BACKEND_DIR
    db_path: Path = BACKEND_DIR / "data" / "daggers.db"
    evidence_dir: Path = BACKEND_DIR / "data" / "evidence"
    gallery_dir: Path = BACKEND_DIR / "data" / "gallery"
    web_dir: Path = ROOT / "web"

    mode: str = "live"
    environment: str = "dev"
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

    # ---- integration: environment, security, abuse controls
    app_env: str = "dev"                 # dev | production (both live)
    phishtank_key: str = ""
    search_live_enabled: bool = False
    maps_live_enabled: bool = False
    serper_api_key: str = ""
    google_places_api_key: str = ""
    gemini_key: str = ""
    groq_key: str = ""
    nextdns_api_key: str = ""
    nextdns_profile: str = ""
    guard_dns_hostname: str = ""
    guard_max_age_days: int = 30
    # Live Guard (backend/app/guard/)
    guard_enabled: bool = True
    guard_doh_enabled: bool = False           # RFC 8484 /dns-query on this server
    guard_upstream_doh: str = "https://cloudflare-dns.com/dns-query"
    guard_verdict_ip: str = ""                # VPS mode: blocked A answers point at your verdict server
    guard_doh_block_mode: str = "nxdomain"    # nxdomain | zero (A 0.0.0.0 / AAAA ::)
    guard_doh_rate_per_min: int = 600         # per client (in-memory, hashed key — nothing stored)
    guard_sync_debounce_s: float = 3.0        # bursts of new listings coalesce into one sync
    guard_sync_cooldown_s: float = 30.0       # manual "Sync now" cooldown
    guard_public_origin: str = ""             # e.g. https://daggers.example.org (else from the request)
    # Which analyses may list a domain (GUARD_SOURCES, comma-separated).
    guard_sources: tuple = ("radar", "sweep", "checker", "investigation", "seed")
    official_snapshot_dir: Path = BACKEND_DIR / "data" / "official_snapshots"
    official_registry_path: Path | None = None   # default: backend/app/channels/official/registry.yaml
    # Independent site reputation (Tranco top-sites list) — the SAFE path for widely used,
    # non-government sites. The list is DATA downloaded at run time; none ships in the code.
    reputation_list_path: Path | None = None  # None → reputation path off (from_env: backend/data/reputation/top-sites.csv)
    reputation_top_n: int = 60_000
    reputation_max_age_days: int = 45
    reputation_auto_update: bool = False      # from_env default: ON (download when missing/older than 7 days)
    # Live Checker evidence (from_env defaults: ON). Off in directly-constructed Settings (tests).
    check_rdap_enabled: bool = False          # domain registration age via RDAP (registrable domain only)
    check_page_fetch_enabled: bool = False    # secure read-only retrieval of the checked link (markup only)
    check_evidence_deadline_s: float = 10.0
    check_ct_enabled: bool = False            # certificate-transparency "in use since" (from_env: ON)
    ct_api_url: str = "https://api.certspotter.com/v1/issuances"
    ct_api_key: str = ""                      # optional; without it the provider limits lookups per hour
    # The Checker's own result store (independent of the Police Portal database).
    checker_store_path: Path | None = None    # None → in memory (from_env: backend/data/checker-store.db)
    check_cache_ttl_s: int = 21600            # reuse a completed result for 6 h (0 = never reuse)
    check_cache_partial_ttl_s: int = 600      # when a source could not be checked: 10 min
    check_dedup_seconds: int = 120            # no longer used (replaced by the Checker result store)
    local_open_access: bool = False      # dev only: same-machine browser = local admin, no login
    cookie_secure: bool = False          # true in production (HTTPS only)
    session_ttl_hours: int = 12
    scan_rate_per_min: int = 60
    login_max_failures: int = 5
    trust_proxy_headers: bool = False    # honour X-Forwarded-For only behind your own proxy

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = env if env is not None else os.environ
        app_env = env.get("APP_ENV", "dev").strip().lower() or "dev"
        if app_env not in {"dev", "production"}:
            app_env = "dev"
        production = app_env == "production"
        return cls(
            app_env=app_env,
            phishtank_key=env.get("PHISHTANK_KEY", ""),
            search_live_enabled=_bool("SEARCH_LIVE_ENABLED", False, env),
            maps_live_enabled=_bool("MAPS_LIVE_ENABLED", False, env),
            serper_api_key=env.get("SERPER_API_KEY", ""),
            google_places_api_key=env.get("GOOGLE_PLACES_API_KEY", ""),
            gemini_key=env.get("GEMINI_KEY", ""),
            groq_key=env.get("GROQ_KEY", ""),
            nextdns_api_key=env.get("NEXTDNS_API_KEY", ""),
            nextdns_profile=(env.get("NEXTDNS_PROFILE_ID") or env.get("NEXTDNS_PROFILE") or "").strip(),
            guard_dns_hostname=_guard_hostname(env),
            guard_max_age_days=max(1, _int("GUARD_MAX_AGE_DAYS", 30, env)),
            guard_enabled=_bool("GUARD_ENABLED", True, env),
            guard_doh_enabled=_bool("GUARD_DOH_ENABLED", False, env),
            guard_upstream_doh=(env.get("GUARD_UPSTREAM_DOH") or "https://cloudflare-dns.com/dns-query").strip(),
            guard_verdict_ip=(env.get("GUARD_VERDICT_IP") or "").strip(),
            guard_doh_block_mode=(env.get("GUARD_DOH_BLOCK_MODE") or "nxdomain").strip().lower(),
            guard_doh_rate_per_min=max(10, _int("GUARD_DOH_RATE_PER_MIN", 600, env)),
            guard_sync_debounce_s=min(max(0.5, _float("GUARD_SYNC_DEBOUNCE_S", 3.0, env)), 60.0),
            guard_sync_cooldown_s=min(max(5.0, _float("GUARD_SYNC_COOLDOWN_S", 30.0, env)), 3600.0),
            guard_public_origin=(env.get("GUARD_PUBLIC_ORIGIN") or "").strip().rstrip("/"),
            guard_sources=tuple(x.strip().lower() for x in (env.get("GUARD_SOURCES")
                                or "radar,sweep,checker,investigation,seed").split(",") if x.strip()),
            official_snapshot_dir=_path("OFFICIAL_SNAPSHOT_DIR", BACKEND_DIR / "data" / "official_snapshots", env),
            official_registry_path=_path("OFFICIAL_REGISTRY_PATH", BACKEND_DIR / "app" / "channels" / "official" / "registry.yaml", env),
            reputation_list_path=_path("REPUTATION_LIST_PATH", BACKEND_DIR / "data" / "reputation" / "top-sites.csv", env),
            reputation_top_n=min(max(100, _int("REPUTATION_TOP_N", 60_000, env)), 100_000),
            reputation_max_age_days=min(max(1, _int("REPUTATION_MAX_AGE_DAYS", 45, env)), 365),
            reputation_auto_update=_bool("REPUTATION_AUTO_UPDATE", True, env),
            check_rdap_enabled=_bool("CHECK_RDAP_ENABLED", True, env),
            check_page_fetch_enabled=_bool("CHECK_PAGE_FETCH_ENABLED", True, env),
            check_evidence_deadline_s=min(max(2.0, _float("CHECK_EVIDENCE_DEADLINE_S", 10.0, env)), 20.0),
            check_ct_enabled=_bool("CHECK_CT_ENABLED", True, env),
            ct_api_url=(env.get("CT_API_URL") or "https://api.certspotter.com/v1/issuances").strip(),
            ct_api_key=(env.get("CT_API_KEY") or "").strip(),
            checker_store_path=_path("CHECKER_STORE_PATH", BACKEND_DIR / "data" / "checker-store.db", env),
            check_cache_ttl_s=min(max(0, _int("CHECK_CACHE_TTL_S", 21600, env)), 7 * 86400),
            check_cache_partial_ttl_s=min(max(0, _int("CHECK_CACHE_PARTIAL_TTL_S", 600, env)), 86400),
            check_dedup_seconds=max(0, _int("CHECK_DEDUP_SECONDS", 120, env)),
            local_open_access=False if production else _bool("LOCAL_OPEN_ACCESS", False, env),
            cookie_secure=_bool("COOKIE_SECURE", production, env),
            session_ttl_hours=max(1, min(_int("SESSION_TTL_HOURS", 12, env), 72)),
            scan_rate_per_min=max(1, _int("SCAN_RATE_PER_MIN", 60, env)),
            login_max_failures=max(1, _int("LOGIN_MAX_FAILURES", 5, env)),
            trust_proxy_headers=_bool("TRUST_PROXY_HEADERS", False, env),
            db_path=_path("DB_PATH", BACKEND_DIR / "data" / "daggers.db", env),
            evidence_dir=_path("EVIDENCE_DIR", BACKEND_DIR / "data" / "evidence", env),
            gallery_dir=_path("GALLERY_DIR", BACKEND_DIR / "data" / "gallery", env),
            web_dir=_path("WEB_DIR", ROOT / "web", env),
            mode="live",
            environment=app_env,
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
            guard_block_misleading=_bool("GUARD_INCLUDE_MISLEADING", _bool("GUARD_BLOCK_MISLEADING", False, env), env),
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

    def adapter_status(self) -> dict[str, dict[str, bool | str]]:
        """Public readiness flags only — never expose secret values."""
        return {
            "crt": {"enabled": self.crt_enabled, "configured": True},
            "feeds": {"enabled": self.feeds_enabled, "configured": bool(self.phishtank_key), "fallback_sources": True},
            "enrich": {"enabled": self.enrich_enabled, "configured": True},
            "render": {"enabled": self.render_enabled, "configured": True},
            "search": {"enabled": self.search_live_enabled, "configured": bool(self.serper_api_key),
                       "fallback_source": True},
            "maps": {"enabled": self.maps_live_enabled, "configured": bool(self.google_places_api_key)},
            "ai": {"enabled": self.ai_state == "live", "configured": bool(self.gemini_key or self.groq_key),
                   "state": self.ai_state, "template_fallback": True},
            "guard": {"enabled": True, "configured": bool(self.nextdns_api_key and self.nextdns_profile),
                      "hostname": self.guard_dns_hostname, "manual_sync": True},
        }

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
