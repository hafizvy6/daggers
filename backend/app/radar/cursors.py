from __future__ import annotations

import json
from typing import Any


class Cursors:
    """Resumable poller state in the meta table; no SQL escapes this class."""

    def __init__(self, repo) -> None:
        self.repo = repo

    def _key(self, name: str) -> str:
        return f"cursor.{name}"

    def get(self, name: str, default: Any = None) -> Any:
        raw = self.repo.get_meta(self._key(name))
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def set(self, name: str, value: Any) -> None:
        self.repo.set_meta(self._key(name), value if isinstance(value, str) else json.dumps(value))

    def get_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self.get(name, default))
        except (TypeError, ValueError):
            return default

    def set_int(self, name: str, value: int) -> None:
        self.set(name, int(value))
