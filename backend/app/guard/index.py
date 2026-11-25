"""O(1) in-memory block index: exact host, plus the registrable site covering its sub-domains."""
from __future__ import annotations

import threading

from ..intel import psl as psl_mod


class GuardIndex:
    def __init__(self) -> None:
        self._entries: dict[str, dict] = {}
        self._lock = threading.RLock()

    def replace(self, rows: list[dict]) -> None:
        fresh = {r["domain"]: r for r in rows}
        with self._lock:
            self._entries = fresh

    def put(self, row: dict) -> None:
        with self._lock:
            self._entries[row["domain"]] = row

    def drop(self, domain: str) -> None:
        with self._lock:
            self._entries.pop(domain, None)

    def __len__(self) -> int:
        return len(self._entries)

    def domains(self) -> list[str]:
        with self._lock:
            return sorted(self._entries)

    def rows(self) -> list[dict]:
        with self._lock:
            return list(self._entries.values())

    def match(self, qname: str) -> dict | None:
        """The listed entry that blocks `qname`, or None. Exact host first; then each parent, but a
        parent blocks its sub-domains only when it is a registrable site (not a shared platform)."""
        name = (qname or "").strip().lower().rstrip(".")
        if not name:
            return None
        entries = self._entries
        hit = entries.get(name)
        if hit is not None:
            return hit
        labels = name.split(".")
        psl = psl_mod.default()
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            row = entries.get(parent)
            if row is not None and psl.site(parent) == parent and not psl.platform(parent):
                return row
        return None
