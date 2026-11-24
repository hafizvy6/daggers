from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from ..catalog import Catalog
from ..config import Settings
from ..core import scorer
from .cursors import Cursors


class PhishFeeds:
    """PhishTank/OpenPhish/URLhaus labels with a committed fixture fallback."""

    SOURCES = (
        ("OpenPhish", "https://openphish.com/feed.txt"),
        ("URLhaus", "https://urlhaus.abuse.ch/downloads/text_online/"),
    )

    def __init__(self, settings: Settings, catalog: Catalog, repo, cursors: Cursors) -> None:
        self.settings = settings
        self.catalog = catalog
        self.repo = repo
        self.cursors = cursors
        self._cache: set[str] = set()

    def fixture_domains(self) -> set[str]:
        path = self.settings.seed_dir / "fixtures" / "phishtank.json"
        if not path.exists():
            return set()
        data = json.loads(path.read_text(encoding="utf-8"))
        domains: set[str] = set()
        for item in data:
            value = item.get("domain") if isinstance(item, dict) else item
            normalized = self._registrable(str(value))
            if normalized:
                domains.add(normalized)
        return domains

    def _registrable(self, value: str) -> str | None:
        candidate = value.strip().lower().replace("hxxp://", "http://").replace("hxxps://", "https://")
        if not candidate:
            return None
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        host = (urlparse(candidate).hostname or "").strip().rstrip(".")
        if not host:
            return None
        normalized = scorer.normalize_url(host, self.catalog.suffix_resolver)
        return normalized.registrable_domain or normalized.unicode_host or None

    async def poll_once(self, mode: str = "live") -> set[str]:
        if mode == "demo":
            self._cache = self.fixture_domains()
            return set(self._cache)
        if not self.settings.feeds_enabled:
            self._cache = self.repo.confirmed_domains()
            return set(self._cache)

        domains: set[str] = set()
        headers = {"User-Agent": self.settings.http_user_agent}
        async with httpx.AsyncClient(timeout=self.settings.http_timeout_s, headers=headers) as client:
            for source, url in self.SOURCES:
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                except Exception:
                    continue
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    domain = self._registrable(line)
                    if domain:
                        domains.add(domain)
        self._cache = domains or self.fixture_domains()
        if self._cache:
            self.repo.upsert_feed_labels(self._cache, source="feeds")
        self.cursors.set("feed_last_count", len(self._cache))
        return set(self._cache)

    def is_confirmed(self, domain: str) -> bool:
        return str(domain).lower() in self._cache
