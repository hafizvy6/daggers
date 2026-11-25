"""The Checker's own result store (separate SQLite file, never the Police Portal database).
SQL lives in ``repo.py`` (project rule: SQL only in repo modules)."""
from .repo import REQUEST_TTL_S, CheckerStore, result_key

__all__ = ["CheckerStore", "result_key", "REQUEST_TTL_S"]
