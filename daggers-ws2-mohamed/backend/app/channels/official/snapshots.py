"""Content-addressed, append-only snapshot store for retrieved official records.

Layout under ``root``::

    objects/<sha[:2]>/<sha>.txt     exact retrieved text (never rewritten)
    index.jsonl                     one JSON line per retrieval (append-only)

A retrieval failure is recorded in the index with ``fetch_status: "error"`` and
no object, so it can never be confused with a successful retrieval.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

from .models import OfficialRecord, RegistryEntry, sha256_text

DEFAULT_SNAPSHOT_DIR = Path(__file__).resolve().parents[4] / "backend" / "data" / "official_snapshots"


class SnapshotStore:
    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root else DEFAULT_SNAPSHOT_DIR
        self.objects = self.root / "objects"
        self.index = self.root / "index.jsonl"

    def _object_path(self, digest: str) -> Path:
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            raise ValueError("invalid content digest")
        return self.objects / digest[:2] / f"{digest}.txt"

    def put_content(self, content: str) -> str:
        """Store bytes under their SHA-256. Existing objects are never overwritten."""
        digest = sha256_text(content)
        path = self._object_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            return digest
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        return digest

    def get_content(self, digest: str) -> str | None:
        path = self._object_path(digest)
        if not path.exists():
            return None
        content = path.read_text(encoding="utf-8")
        if sha256_text(content) != digest:
            raise ValueError(f"snapshot object {digest} is corrupted")
        return content

    def _append(self, row: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        with open(self.index, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def record(self, record: OfficialRecord) -> dict:
        row = {
            "record_id": record.record_id,
            "entry_id": record.entry_id,
            "url": record.url,
            "title": record.title,
            "published_at": record.published_at,
            "retrieved_at": record.retrieved_at,
            "fetch_status": record.fetch_status,
            "fetch_error": record.fetch_error,
            "synthetic": record.synthetic,
            "content_sha256": None,
        }
        if record.fetch_status == "ok":
            row["content_sha256"] = self.put_content(record.content)
        self._append(row)
        return row

    def rows(self) -> list[dict]:
        if not self.index.exists():
            return []
        rows = []
        with open(self.index, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    def latest_records(self, entry_ids: Iterable[str]) -> list[OfficialRecord]:
        """Latest retrieval per (entry, url). Failures are returned as error records."""
        wanted = set(entry_ids)
        latest: dict[tuple[str, str], dict] = {}
        for row in self.rows():
            if row.get("entry_id") in wanted:
                latest[(row["entry_id"], row["url"])] = row
        records: list[OfficialRecord] = []
        for row in latest.values():
            content = ""
            status = row.get("fetch_status", "error")
            error = row.get("fetch_error")
            if status == "ok":
                loaded = self.get_content(row.get("content_sha256") or "")
                if loaded is None:
                    status, error = "error", "snapshot object missing"
                else:
                    content = loaded
            records.append(
                OfficialRecord(
                    record_id=row["record_id"],
                    entry_id=row["entry_id"],
                    url=row["url"],
                    content=content,
                    retrieved_at=row["retrieved_at"],
                    published_at=row.get("published_at"),
                    title=row.get("title") or "",
                    fetch_status=status,
                    fetch_error=error,
                    synthetic=bool(row.get("synthetic")),
                )
            )
        return records

    def provider(self):
        """RecordProvider for ShieldScorer: reads only what was actually retrieved."""

        def provide(entries: list[RegistryEntry]) -> list[OfficialRecord]:
            return self.latest_records(entry.id for entry in entries)

        return provide
