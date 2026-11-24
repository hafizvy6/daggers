"""Sweep service: run default (or opted-in arbitrary) queries over web/maps channels.

Abuse protections:
  * default queries only, from ``queries.yaml``; arbitrary text requires SWEEP_ALLOW_ARBITRARY=1
  * arbitrary queries are length-capped and refused if they contain personal data
  * per-client sliding-window rate limit + global concurrency cap
  * result titles/snippets are PII-redacted before storage
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

import yaml

from . import privacy, trust_policy, urls
from .sweep_store import SweepStore, make_store

QUERIES_PATH = Path(__file__).resolve().with_name("queries.yaml")
CHANNELS = ("web", "maps")
MAX_QUERY_LEN = 120


class SweepError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def load_queries(path: Path = QUERIES_PATH) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    queries = []
    seen = set()
    for item in data.get("queries") or []:
        if item.get("channel") not in CHANNELS or item.get("lang") not in ("en", "ar") or not item.get("query"):
            raise ValueError(f"invalid sweep query {item!r}")
        if item["id"] in seen:
            raise ValueError(f"duplicate sweep query id {item['id']}")
        if privacy.pii_kinds(item["query"]):
            raise ValueError(f"sweep query {item['id']} contains personal data")
        seen.add(item["id"])
        queries.append(dict(item))
    return queries


class RateLimiter:
    def __init__(self, per_minute: int = 6, max_concurrent: int = 2, clock: Callable[[], float] = time.monotonic):
        self.per_minute = per_minute
        self.clock = clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def check(self, client: str) -> None:
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(client or "unknown", deque())
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= self.per_minute:
                raise SweepError(429, "sweep rate limit exceeded; try again in a minute")
            hits.append(now)
            if len(self._hits) > 5000:  # bound memory under address churn
                for key in list(self._hits)[:1000]:
                    self._hits.pop(key, None)

    def slot(self):
        if not self._slots.acquire(blocking=False):
            raise SweepError(503, "sweep capacity busy; try again shortly")
        return self._slots


def _counts(tags: list[str]) -> dict[str, int]:
    return {tag: tags.count(tag) for tag in trust_policy.TAGS}


class SweepService:
    def __init__(
        self,
        *,
        search_channel,
        maps_channel,
        store: SweepStore | None = None,
        queries: list[dict] | None = None,
        allow_arbitrary: bool | None = None,
        limiter: RateLimiter | None = None,
        publish: Callable[[str, dict], None] | None = None,
    ) -> None:
        self.search = search_channel
        self.maps = maps_channel
        self.store = store or make_store()
        self.queries = queries if queries is not None else load_queries()
        self.allow_arbitrary = (
            os.environ.get("SWEEP_ALLOW_ARBITRARY", "0") == "1" if allow_arbitrary is None else allow_arbitrary
        )
        self.limiter = limiter or RateLimiter(
            per_minute=int(os.environ.get("SWEEP_RATE_PER_MIN", "6") or 6),
            max_concurrent=int(os.environ.get("SWEEP_MAX_CONCURRENT", "2") or 2),
        )
        self.publish = publish

    # ---- request resolution

    def resolve(self, channel: str, query_id: str | None, query: str | None, lang: str) -> dict:
        if channel not in CHANNELS:
            raise SweepError(422, "channel must be 'web' or 'maps'")
        if lang not in ("en", "ar"):
            raise SweepError(422, "lang must be 'en' or 'ar'")
        if query_id:
            for item in self.queries:
                if item["id"] == query_id:
                    if item["channel"] != channel:
                        raise SweepError(422, f"query '{query_id}' belongs to channel '{item['channel']}'")
                    return item
            raise SweepError(404, "unknown query_id")
        if query:
            text = urls.normalize_query(query, MAX_QUERY_LEN + 1)
            for item in self.queries:  # an exact default query is always allowed
                if item["channel"] == channel and item["query"].casefold() == text.casefold():
                    return item
            if not self.allow_arbitrary:
                raise SweepError(403, "arbitrary queries are disabled (set SWEEP_ALLOW_ARBITRARY=1 to opt in)")
            if len(text) > MAX_QUERY_LEN or len(text) < 3:
                raise SweepError(422, f"query must be 3–{MAX_QUERY_LEN} characters")
            kinds = privacy.pii_kinds(text)
            if kinds:
                raise SweepError(422, f"query looks like it contains personal data ({', '.join(kinds)}); refused")
            return {"id": None, "channel": channel, "lang": lang, "query": text}
        for item in self.queries:
            if item["channel"] == channel and item["lang"] == lang:
                return item
        for item in self.queries:
            if item["channel"] == channel:
                return item
        raise SweepError(404, "no default query configured for this channel")

    # ---- execution

    def run(self, *, channel: str, lang: str = "en", query_id: str | None = None,
            query: str | None = None, client: str = "unknown") -> dict:
        spec = self.resolve(channel, query_id, query, lang)
        self.limiter.check(client)
        slots = self.limiter.slot()
        try:
            if channel == "web":
                run = self.search.run(spec["query"], spec["lang"])
                engine, cached, kind, errors = run.engine, run.cached, run.source_kind, run.errors
                rows = [self._web_row(r) for r in run.results]
            else:
                result = self.maps.run(spec["query"], spec["lang"])
                engine, cached, kind, errors = result["engine"], result["cached"], result["source_kind"], result["errors"]
                rows = [self._maps_row(i, item) for i, item in enumerate(result["listings"], 1)]
        finally:
            slots.release()
        meta = self.store.create_run(query=spec["query"], lang=spec["lang"], channel=channel, engine=engine, cached=cached)
        self.store.add_results(meta["id"], rows)
        response = self._response(meta, rows, kind, errors, spec.get("id"))
        if self.publish:
            try:
                self.publish("sweep", {k: response[k] for k in ("id", "channel", "query_id", "source_kind", "counts", "created_at")})
            except Exception:  # SSE is best-effort; never fail the sweep
                pass
        return response

    def get(self, run_id: int) -> dict | None:
        run = self.store.get_run(run_id)
        if run is None:
            return None
        rows = run.pop("results", [])
        if rows:
            kind = rows[0]["source_kind"]
        elif run.get("engine") == "none":
            kind = "unconfigured"
        else:
            kind = "unavailable"
        return self._response(run, rows, kind, [], run.get("query_id"))

    def _response(self, meta: dict, rows: list[dict], kind: str, errors: list[str], query_id) -> dict:
        return {
            "id": meta["id"],
            "query": meta["query"],
            "query_id": query_id,
            "lang": meta["lang"],
            "channel": meta["channel"],
            "engine": meta["engine"],
            "cached": bool(meta["cached"]),
            "source_kind": kind,
            "synthetic": False,
            "created_at": meta["created_at"],
            "store": self.store.backend,
            "counts": _counts([r["tag"] for r in rows]),
            "errors": errors,
            "results": rows,
        }

    @staticmethod
    def _web_row(r: dict) -> dict:
        return {
            "position": r["position"], "url": r["url"], "title": r["title"], "snippet": r["snippet"],
            "verdict": r["verdict"], "score": r["score"], "reasons": r["reasons"], "finding_id": None,
            "tag": r["tag"], "manual_review": r["manual_review"], "domain_auth": r["domain_auth"],
            "gov_verification": r["gov_verification"], "trust_reasons": r["trust_reasons"],
            "blockable": r["blockable"], "source_kind": r["source_kind"], "maps": None,
        }

    @staticmethod
    def _maps_row(position: int, item: dict) -> dict:
        listing, checks = item["listing"], item["checks"]
        website = checks["website"]
        return {
            "position": position,
            "url": website.get("url") or f"maps:{listing['provider']}:{listing['provider_place_id']}",
            "title": listing["name"],
            "snippet": " · ".join(x for x in (listing["category"], listing["address"]) if x),
            "verdict": website.get("verdict") or checks["phone"].get("verdict") or "UNKNOWN",
            "score": website.get("score") or checks["phone"].get("score") or 0.0,
            "reasons": list(website.get("reasons") or []) + list(item["reasons"]),
            "finding_id": None,
            "tag": item["tag"], "manual_review": item["manual_review"],
            "domain_auth": website.get("domain_auth"), "gov_verification": None,
            "trust_reasons": list(website.get("trust_reasons") or []),
            "blockable": item["blockable"],
            "source_kind": listing.get("source_kind") or "live",
            "maps": {"listing": listing, "checks": checks},
        }
