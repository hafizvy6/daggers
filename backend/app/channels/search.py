"""Search channel adapter.

Provider chain (first success wins), only when SEARCH_LIVE_ENABLED=1:
  1. Serper (Google results)  — when SERPER_API_KEY is set
  2. DuckDuckGo HTML          — keyless fallback live source

Every result is normalized, deduplicated, PII-redacted, and scored by the shared
Shared brain + trust policy (``ShieldScorer``). There is no separate scoring
engine here. With no live provider configured the run is empty and source_kind
is ``unconfigured``; a configured provider that fails is ``unavailable``.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Protocol
from urllib.parse import urlencode

from . import privacy, urls
from .http_client import ProviderError
from .http_client import request as http_request

MAX_RESULTS = 10


@dataclass
class RawResult:
    url: str
    title: str = ""
    snippet: str = ""


@dataclass
class SearchRun:
    query: str
    lang: str
    engine: str
    source_kind: str  # live | cached | unconfigured | unavailable
    cached: bool
    results: list[dict] = field(default_factory=list)
    rejected: int = 0
    errors: list[str] = field(default_factory=list)


class SearchProvider(Protocol):
    name: str
    source_kind: str

    def search(self, query: str, lang: str, limit: int) -> list[RawResult]: ...


class SerperProvider:
    name, source_kind = "serper", "live"

    def __init__(self, api_key: str, http: Callable = http_request) -> None:
        self.api_key = api_key
        self.http = http

    def search(self, query: str, lang: str, limit: int) -> list[RawResult]:
        body = self.http(
            "https://google.serper.dev/search",
            method="POST",
            headers={"X-API-KEY": self.api_key},
            json_body={"q": query, "gl": "ae", "hl": lang, "num": limit},
        )
        data = json.loads(body)
        # Organic results only — ads, maps/local packs and knowledge panels are ignored.
        return [
            RawResult(str(item.get("link", "")), str(item.get("title", "")), str(item.get("snippet", "")))
            for item in data.get("organic", [])[:limit]
        ]


class _DDGParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[RawResult] = []
        self._field: str | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = (attrs.get("class") or "").split()
        if tag == "a" and "result__a" in classes:
            self.results.append(RawResult(attrs.get("href") or ""))
            self._field = "title"
        elif "result__snippet" in classes and self.results:
            self._field = "snippet"

    def handle_endtag(self, tag):
        if tag in ("a", "td", "div"):
            self._field = None

    def handle_data(self, data):
        if self._field and self.results:
            item = self.results[-1]
            setattr(item, self._field, getattr(item, self._field) + data)


def parse_ddg_html(html: str) -> list[RawResult]:
    parser = _DDGParser()
    parser.feed(html)
    return [r for r in parser.results if r.url and "y.js" not in r.url]  # drop DDG ad redirects


class DuckDuckGoProvider:
    name, source_kind = "duckduckgo", "live"

    def __init__(self, http: Callable = http_request) -> None:
        self.http = http

    def search(self, query: str, lang: str, limit: int) -> list[RawResult]:
        region = "xa-ar" if lang == "ar" else "xa-en"
        body = self.http(
            "https://html.duckduckgo.com/html/",
            method="POST",
            form=urlencode({"q": query, "kl": region}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        return parse_ddg_html(body.decode("utf-8", errors="replace"))[:limit]


class TTLCache:
    def __init__(self, ttl_s: float = 900, max_items: int = 256, clock: Callable[[], float] = time.monotonic):
        self.ttl_s, self.max_items, self.clock = ttl_s, max_items, clock
        self._data: dict[tuple, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple):
        with self._lock:
            item = self._data.get(key)
            if not item or self.clock() - item[0] > self.ttl_s:
                self._data.pop(key, None)
                return None
            return item[1]

    def put(self, key: tuple, value: object) -> None:
        with self._lock:
            if len(self._data) >= self.max_items:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (self.clock(), value)


def default_providers(env: dict | None = None) -> list:
    env = dict(os.environ if env is None else env)
    providers: list = []
    if env.get("SEARCH_LIVE_ENABLED", "0") == "1":
        if env.get("SERPER_API_KEY"):
            providers.append(SerperProvider(env["SERPER_API_KEY"]))
        providers.append(DuckDuckGoProvider())
    return providers


class SearchChannel:
    def __init__(self, scorer, providers: list | None = None, cache: TTLCache | None = None) -> None:
        self.scorer = scorer
        self.providers = providers if providers is not None else default_providers()
        self.cache = cache or TTLCache()

    def _fetch(self, query: str, lang: str, limit: int) -> tuple[list[RawResult], str, str, bool, list[str]]:
        errors: list[str] = []
        if not self.providers:
            return [], "none", "unconfigured", False, ["search: no live provider configured"]
        for provider in self.providers:
            key = (provider.name, query.casefold(), lang, limit)
            if provider.source_kind == "live":
                cached = self.cache.get(key)
                if cached is not None:
                    return cached, provider.name, "cached", True, errors  # type: ignore[return-value]
            try:
                raw = provider.search(query, lang, limit)
            except (ProviderError, ValueError, KeyError, OSError) as exc:
                errors.append(f"{provider.name}: {type(exc).__name__}")
                continue
            if provider.source_kind == "live":
                if not raw:
                    errors.append(f"{provider.name}: no results")
                    continue
                self.cache.put(key, raw)
            return raw, provider.name, provider.source_kind, False, errors
        return [], "none", "unavailable", False, errors

    def run(self, query: str, lang: str = "en", limit: int = MAX_RESULTS) -> SearchRun:
        query = urls.normalize_query(query)
        limit = max(1, min(limit, MAX_RESULTS))
        raw, engine, kind, cached, errors = self._fetch(query, lang, limit)
        run = SearchRun(query, lang, engine, kind, cached, errors=errors)
        seen: set[str] = set()
        for item in raw:
            url, problem = urls.normalize_result_url(item.url)
            if not url:
                run.rejected += 1
                continue
            key = urls.dedupe_key(url)
            if key in seen:
                continue
            seen.add(key)
            title = privacy.redact(item.title, 200)
            snippet = privacy.redact(item.snippet, 400)
            assessed = self.scorer.assess_url(url, text=f"{title}. {snippet}")
            run.results.append({
                "position": len(run.results) + 1,
                "url": url,
                "registrable_domain": urls.registrable_domain(url, self.scorer.catalog.suffix_resolver),
                "title": title,
                "snippet": snippet,
                "source_kind": kind,
                **{k: assessed[k] for k in (
                    "verdict", "score", "reasons", "scam_type", "tag", "manual_review",
                    "domain_auth", "gov_verification", "trust_reasons", "blockable", "policy_version")},
            })
        return run
