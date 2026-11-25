"""The Checker's OWN result store — independent of the Police Portal database.

The Checker never reads the Portal: it analyses, SENDS the result to the Portal, and keeps its own
copy here. When the same input is checked again, the stored result is returned directly (no new
analysis, nothing sent again).

A result is reused only while it is still valid:
* the key includes the normalised input, language, engine version, trust-policy version, registry
  version and reputation-list version — approving / revoking a registry entry or installing a new
  ranking list makes every older result miss automatically (re-analysed on the next check);
* each result expires: ``CHECK_CACHE_TTL_S`` (default 6 h) when every check completed,
  ``CHECK_CACHE_PARTIAL_TTL_S`` (default 10 min) when a source (RDAP, page, feeds) could not be
  checked — so a temporary outage is retried soon;
* ``CHECK_CACHE_TTL_S=0`` switches reuse off (every check is analysed; request-id idempotency stays).

What is stored is exactly the response the user received (already redacted: personal data removed
from messages). Only a hash of the input is used as the key.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    key         TEXT PRIMARY KEY,
    response    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    request_id  TEXT PRIMARY KEY,
    response    TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_expiry ON results(expires_at);
CREATE INDEX IF NOT EXISTS idx_requests_expiry ON requests(expires_at);
"""
REQUEST_TTL_S = 24 * 3600          # a repeated click / refresh with the same request id


def result_key(input_type: str, value: str, lang: str, versions: dict) -> str:
    material = json.dumps({"t": input_type, "v": " ".join(value.strip().lower().split()), "l": lang,
                           **{k: versions.get(k) for k in sorted(versions)}}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class CheckerStore:
    def __init__(self, path: Path | None) -> None:
        """`path=None` → in-memory (tests / no writable data directory)."""
        self.path = path
        self._lock = threading.Lock()
        target = ":memory:"
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            target = str(path)
        self._conn = sqlite3.connect(target, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL") if path is not None else None
        self._conn.executescript(SCHEMA)
        self._last_prune = 0.0

    # ------------------------------------------------------------------ reads (own store only)

    def by_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT response FROM requests WHERE request_id = ? AND expires_at > ?",
                                     (request_id, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def get(self, key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT response, created_at FROM results WHERE key = ? AND expires_at > ?",
                                     (key, time.time())).fetchone()
        if not row:
            return None
        out = json.loads(row[0])
        out["cached"] = True
        out["cached_at"] = row[1]
        return out

    # ------------------------------------------------------------------ writes

    def put(self, key: str | None, request_id: str, response: dict, ttl_s: float) -> None:
        now = time.time()
        body = json.dumps(response, ensure_ascii=False, default=str)
        created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock, self._conn:
            if key and ttl_s > 0:
                self._conn.execute("INSERT OR REPLACE INTO results(key, response, created_at, expires_at) "
                                   "VALUES(?, ?, ?, ?)", (key, body, created, now + ttl_s))
            self._conn.execute("INSERT OR REPLACE INTO requests(request_id, response, expires_at) VALUES(?, ?, ?)",
                               (request_id, body, now + REQUEST_TTL_S))
            if now - self._last_prune > 300:
                self._conn.execute("DELETE FROM results WHERE expires_at <= ?", (now,))
                self._conn.execute("DELETE FROM requests WHERE expires_at <= ?", (now,))
                self._last_prune = now

    def remember_request(self, request_id: str, response: dict) -> None:
        self.put(None, request_id, response, 0)

    def reset_if_build_changed(self, build: str) -> bool:
        """Clear every stored result when the application build changed. → True if cleared."""
        with self._lock, self._conn:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'build'").fetchone()
            if row and row[0] == build:
                return False
            self._conn.execute("DELETE FROM results")
            self._conn.execute("DELETE FROM requests")
            self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('build', ?)", (build,))
        return True

    def stats(self) -> dict:
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*) FROM results WHERE expires_at > ?", (time.time(),)).fetchone()[0]
        return {"stored_results": int(n), "path": str(self.path) if self.path else ":memory:"}

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM results")
            self._conn.execute("DELETE FROM requests")
