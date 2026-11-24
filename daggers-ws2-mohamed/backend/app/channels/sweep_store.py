"""Sweep persistence behind one interface.

``RepoSweepStore`` uses WS1 repository methods when WS1 has added them (see
docs/WS2.md → "Repository methods needed"). Until then ``InMemorySweepStore``
is used. **The in-memory store is TEMPORARY**: runs are lost on restart and are
capped in number. Both stores return the same contract.

Row shape mirrors the existing ``sweep_runs`` / ``sweep_results`` schema; WS2's
additive fields (tag, domain_auth, …) travel in ``detail``.
"""
from __future__ import annotations

import threading
from typing import Protocol

from .official.models import iso, utc_now

REPO_METHODS = ("create_sweep_run", "add_sweep_results", "get_sweep_run")


class SweepStore(Protocol):
    backend: str

    def create_run(self, *, query: str, lang: str, channel: str, engine: str, cached: bool) -> dict: ...
    def add_results(self, run_id: int, results: list[dict]) -> None: ...
    def get_run(self, run_id: int) -> dict | None: ...


class InMemorySweepStore:
    """TEMPORARY in-process store (no SQL). Oldest runs are evicted past ``max_runs``."""

    backend = "memory-temporary"

    def __init__(self, max_runs: int = 200) -> None:
        self.max_runs = max_runs
        self._runs: dict[int, dict] = {}
        self._next = 1
        self._lock = threading.Lock()

    def create_run(self, *, query: str, lang: str, channel: str, engine: str, cached: bool) -> dict:
        with self._lock:
            run = {"id": self._next, "query": query, "lang": lang, "channel": channel, "engine": engine,
                   "cached": bool(cached), "created_at": iso(utc_now()), "results": []}
            self._runs[self._next] = run
            self._next += 1
            while len(self._runs) > self.max_runs:
                self._runs.pop(min(self._runs))
            return {k: v for k, v in run.items() if k != "results"}

    def add_results(self, run_id: int, results: list[dict]) -> None:
        with self._lock:
            if run_id in self._runs:
                self._runs[run_id]["results"].extend(dict(r) for r in results)

    def get_run(self, run_id: int) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            return {**run, "results": [dict(r) for r in run["results"]]}


class RepoSweepStore:
    """Adapter over WS1 ``Repository`` sweep methods (only once WS1 provides them)."""

    backend = "sqlite"

    def __init__(self, repo) -> None:
        missing = [m for m in REPO_METHODS if not callable(getattr(repo, m, None))]
        if missing:
            raise AttributeError(f"repository lacks {missing}")
        self.repo = repo

    def create_run(self, *, query: str, lang: str, channel: str, engine: str, cached: bool) -> dict:
        return self.repo.create_sweep_run(query=query, lang=lang, channel=channel, engine=engine, cached=cached)

    def add_results(self, run_id: int, results: list[dict]) -> None:
        self.repo.add_sweep_results(run_id, results)

    def get_run(self, run_id: int) -> dict | None:
        return self.repo.get_sweep_run(run_id)


def make_store(repo=None) -> SweepStore:
    if repo is not None:
        try:
            return RepoSweepStore(repo)
        except AttributeError:
            pass
    return InMemorySweepStore()
