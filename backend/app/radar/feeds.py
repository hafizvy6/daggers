from __future__ import annotations

from urllib.parse import urlparse

import httpx

from ..catalog import Catalog
from ..config import Settings
from ..core import scorer
from .cursors import Cursors
from ..intel import psl as psl_mod
from ..intel.feeds import url_key


class PhishFeeds:
    """Real bad-URL labels: PhishTank when keyed, then OpenPhish/URLhaus.

    There is no fixture fallback. When the adapter is disabled or every source
    fails, the previously persisted confirmed labels are used and nothing new is
    presented as a live feed.
    """

    SOURCES = (
        ("OpenPhish", "https://openphish.com/feed.txt"),
        ("URLhaus", "https://urlhaus.abuse.ch/downloads/text_online/"),
    )
    PHISHTANK_URL = "https://data.phishtank.com/data/{key}/online-valid.json"

    def __init__(self, settings: Settings, catalog: Catalog, repo, cursors: Cursors) -> None:
        self.settings = settings
        self.catalog = catalog
        self.repo = repo
        self.cursors = cursors
        self._cache: set[str] = set()
        self._url_rows: list[tuple[str, str]] = []
        self._shared: tuple[frozenset[str], frozenset[str]] | None = None

    def _shared_host(self, host: str) -> bool:
        """Hosts where anyone can publish: a listed URL there says nothing about the whole domain."""
        if self._shared is None:
            from ..channels.reputation import SHARED_HOSTS, load_shared_hosts
            self._shared = load_shared_hosts(SHARED_HOSTS)
        hosts, domains = self._shared
        return host in hosts or any(host == d or host.endswith("." + d) for d in domains)

    def _registrable(self, value: str) -> str | None:
        """Feed entry → domain LABEL (host level). The exact URL is always kept separately
        (feed_urls). Shared platforms get no domain-wide label; a tenant of a PSL private suffix
        (shop.github.io) is labelled on its own, never the platform (github.io)."""
        candidate = value.strip().lower().replace("hxxp://", "http://").replace("hxxps://", "https://")
        if not candidate:
            return None
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        try:
            host = (urlparse(candidate).hostname or "").strip().rstrip(".")
        except ValueError:
            return None
        if not host:
            return None
        keyed = url_key(value)
        if keyed:
            self._url_rows.append(keyed)
        if self._shared_host(host):
            return None
        site = psl_mod.default().site(host)
        if site:
            return site
        normalized = scorer.normalize_url(host, self.catalog.suffix_resolver)
        return normalized.registrable_domain or normalized.unicode_host or None

    async def _phishtank_domains(self, client: httpx.AsyncClient) -> set[str]:
        if not self.settings.phishtank_key:
            return set()
        url = self.PHISHTANK_URL.format(key=self.settings.phishtank_key)
        try:
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return set()
        domains: set[str] = set()
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                for key in ("url", "target", "phish_url"):
                    domain = self._registrable(str(item.get(key) or ""))
                    if domain:
                        domains.add(domain)
                        break
        return domains

    async def poll_once(self) -> set[str]:
        if not self.settings.feeds_enabled:
            self._cache = self.repo.confirmed_domains()
            self.cursors.set("feed_last_count", len(self._cache))
            return set(self._cache)

        domains: set[str] = set()
        headers = {"User-Agent": self.settings.http_user_agent}
        async with httpx.AsyncClient(timeout=self.settings.http_timeout_s, headers=headers) as client:
            domains.update(await self._phishtank_domains(client))
            for _source, url in self.SOURCES:
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
        if self._url_rows:
            self.repo.upsert_feed_urls(self._url_rows, source="feeds")
            self._url_rows = []
        if domains:
            self._cache = domains
            self.repo.upsert_feed_labels(domains, source="feeds")
        else:
            self._cache = self.repo.confirmed_domains()
        self.cursors.set("feed_last_count", len(self._cache))
        return set(self._cache)

    def is_confirmed(self, domain: str) -> bool:
        return str(domain).lower() in self._cache
