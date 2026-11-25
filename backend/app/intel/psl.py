"""Public Suffix List (https://publicsuffix.org) — full algorithm: normal, wildcard and exception
rules, ICANN and PRIVATE sections.

The list is DATA: a snapshot ships in ``channels/reputation_data/public_suffix_list.dat`` and
``make reputation-update`` / the reputation auto-update keep a fresher copy in the reputation data
directory (``backend/data/reputation/public_suffix_list.dat``), which is preferred when present.

* ``registrable(host)``        — ICANN registrable domain (what a registrar sells; what RDAP knows)
* ``site(host)``               — registrable domain counting PRIVATE suffixes too, so
                                  ``shop.github.io`` is its own site, not GitHub's
* ``platform(host)``           — the shared platform suffix a host is a tenant of (``github.io``), or None
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
BUNDLED = HERE / "channels" / "reputation_data" / "public_suffix_list.dat"
DATA_COPY = HERE.parents[0] / "data" / "reputation" / "public_suffix_list.dat"


def _ascii(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


@dataclass(frozen=True)
class SuffixMatch:
    suffix: str
    private: bool


class PublicSuffixList:
    def __init__(self, text: str, source: str = "") -> None:
        self.source = source
        self.rules: dict[str, bool] = {}        # rule → private?
        self.wild: dict[str, bool] = {}         # "*.x" stored as x
        self.exceptions: set[str] = set()
        private = False
        for raw in text.splitlines():
            line = raw.strip()
            if "===BEGIN PRIVATE DOMAINS===" in line:
                private = True
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0]
            if rule.startswith("!"):
                self.exceptions.add(_ascii(rule[1:]))
            elif rule.startswith("*."):
                self.wild[_ascii(rule[2:])] = private
            else:
                self.rules[_ascii(rule)] = private
        if len(self.rules) < 1000:
            raise ValueError("public suffix list looks truncated")

    @classmethod
    def load(cls, path: Path | None = None) -> "PublicSuffixList":
        candidates = [path] if path else [DATA_COPY, BUNDLED]
        last: Exception | None = None
        for candidate in candidates:
            if candidate and candidate.exists():
                try:
                    return cls(candidate.read_text(encoding="utf-8"), source=str(candidate))
                except Exception as exc:  # noqa: BLE001 — fall back to the bundled snapshot
                    last = exc
        raise FileNotFoundError(f"no usable public suffix list ({last})")

    def public_suffix(self, host: str, *, include_private: bool) -> SuffixMatch | None:
        """Longest matching public suffix (PSL algorithm). Unknown TLD → the TLD itself (rule '*')."""
        labels = _ascii(host).split(".")
        if not labels or not labels[-1]:
            return None
        best: SuffixMatch | None = None
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                # exception rule: the suffix is the candidate minus its leftmost label
                parent = ".".join(labels[i + 1:])
                return SuffixMatch(parent, self.rules.get(parent, self.wild.get(parent, False)))
            priv = self.rules.get(candidate)
            if priv is not None and (include_private or not priv):
                best = best or SuffixMatch(candidate, priv)
                break
            parent = ".".join(labels[i + 1:])
            wpriv = self.wild.get(parent) if i + 1 <= len(labels) - 1 else None
            if wpriv is not None and (include_private or not wpriv):
                best = best or SuffixMatch(candidate, wpriv)
                break
        if best is None:
            best = SuffixMatch(labels[-1], False)
        return best

    def _registrable(self, host: str, include_private: bool) -> str | None:
        host = _ascii(host)
        match = self.public_suffix(host, include_private=include_private)
        if match is None or host == match.suffix:
            return None
        labels = host.split(".")
        n = len(match.suffix.split("."))
        return ".".join(labels[-(n + 1):])

    def registrable(self, host: str) -> str | None:
        return self._registrable(host, include_private=False)

    def site(self, host: str) -> str | None:
        return self._registrable(host, include_private=True)

    def platform(self, host: str) -> str | None:
        """'shop.github.io' → 'github.io' (the host is a tenant on a shared platform)."""
        match = self.public_suffix(host, include_private=True)
        if match and match.private and _ascii(host) != match.suffix:
            return match.suffix
        return None


_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, PublicSuffixList]] = {}


def default() -> PublicSuffixList:
    """Process-wide list; re-read when the data copy changes (after an update)."""
    key = "default"
    try:
        mtime = DATA_COPY.stat().st_mtime if DATA_COPY.exists() else BUNDLED.stat().st_mtime
    except OSError:
        mtime = 0.0
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] == mtime:
            return cached[1]
        psl = PublicSuffixList.load()
        _CACHE[key] = (mtime, psl)
        return psl


def suffix_resolver(host: str) -> str | None:
    """Resolver for core.scorer: registrable 'site' (tenants of shared platforms are separate sites).
    Returns the Unicode form when the input was Unicode."""
    reg = default().site(host)
    if reg is None:
        return None
    if host and not host.isascii():
        try:
            labels = reg.split(".")
            return ".".join(lbl.encode("ascii").decode("idna") if lbl.startswith("xn--") else lbl for lbl in labels)
        except UnicodeError:
            return reg
    return reg
