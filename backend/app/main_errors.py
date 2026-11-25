"""Errors shared by the runtime and the API layer (kept separate to avoid import cycles)."""
from __future__ import annotations


class CheckFailed(RuntimeError):
    """The Checker could not complete: ``analysis_failed`` or ``persist_failed``."""

    def __init__(self, code: str, message: str, result: dict | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.result = code, message, result
