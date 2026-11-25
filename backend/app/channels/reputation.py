"""Independent site reputation — the SAFE path for widely used, legitimate non-government sites.

A website that is NOT in the official registry can still be SAFE when, independently:

1. its registered domain is ranked in the Tranco top-sites list (a research-grade ranking that
   averages several providers over 30 days, built to resist manipulation; https://tranco-list.eu)
   within the configured top N (default 60,000) — the list must be fresh (default ≤ 45 days);
2. the host is NOT on a shared platform where anyone can publish (Public Suffix List PRIVATE
   section: github.io, blogspot.com, web.app, …) and NOT a form builder, file share, link
   shortener or tunnel (shared_hosts.yaml) — popularity says nothing about such a page;
3. and the central trust policy finds NO scam signal at all (engine verdict UNKNOWN, no suspicious
   content, no threat-feed hit). That part lives in trust_policy.decide(), not here.

Nothing here is a hard-coded allow-list: the ranking is DATA, downloaded by
`make reputation-update` (or automatically by the server when REPUTATION_AUTO_UPDATE=1).
Without a list, or with a stale/corrupt one, no site gets SAFE through this path (fail closed).
Reputation never makes a site "official": government authentication is the registry's job only.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

logger = logging.getLogger("daggers.reputation")

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "reputation_data"
BUNDLED_PSL = DATA_DIR / "public_suffix_list.dat"
SHARED_HOSTS = DATA_DIR / "shared_hosts.yaml"

TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

REPUTABLE = "REPUTABLE"
NOT_RANKED = "NOT_RANKED"
SHARED_HOST = "SHARED_HOST"
LIST_MISSING = "LIST_MISSING"
LIST_STALE = "LIST_STALE"
LIST_INVALID = "LIST_INVALID"

_DOMAIN = re.compile(r"^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
MIN_ROWS = 1000          # a downloaded list shorter than this is treated as broken


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def ascii_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


@dataclass(frozen=True)
class ReputationResult:
    status: str
    host: str
    domain: str | None = None
    rank: int | None = None
    list_id: str | None = None
    list_date: str | None = None
    reason: str = ""

    @property
    def trusted(self) -> bool:
        return self.status == REPUTABLE

    def as_dict(self) -> dict:
        return {"status": self.status, "trusted": self.trusted, "host": self.host, "domain": self.domain,
                "rank": self.rank, "source": "Tranco", "list_id": self.list_id, "list_date": self.list_date,
                "reason": self.reason}


# ------------------------------------------------------------------ shared platforms


def load_private_suffixes(path: Path) -> tuple[frozenset[str], frozenset[str]]:
    """PSL PRIVATE section → (suffix rules, wildcard roots). Each rule marks user-owned sub-domains."""
    rules: set[str] = set()
    wild: set[str] = set()
    inside = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if "===BEGIN PRIVATE DOMAINS===" in line:
            inside = True
            continue
        if "===END PRIVATE DOMAINS===" in line:
            break
        if not inside or not line or line.startswith("//") or line.startswith("!"):
            continue
        rule = ascii_host(line.split()[0])
        if rule.startswith("*."):
            wild.add(rule[2:])
        else:
            rules.add(rule)
    if not rules:
        raise ValueError(f"{path}: no PRIVATE DOMAINS section found")
    return frozenset(rules), frozenset(wild)


def load_shared_hosts(path: Path) -> tuple[frozenset[str], frozenset[str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hosts = frozenset(ascii_host(h) for h in data.get("hosts") or [])
    domains = frozenset(ascii_host(d) for d in data.get("domains") or [])
    return hosts, domains


# ------------------------------------------------------------------ the list


class Reputation:
    def __init__(
        self,
        ranks: dict[str, int] | None = None,
        *,
        meta: dict | None = None,
        path: Path | None = None,
        top_n: int = 60_000,
        max_age_days: int = 45,
        psl_path: Path | None = None,
        shared_path: Path | None = None,
        error: str | None = None,
    ) -> None:
        self.ranks = dict(ranks or {})
        self.meta = dict(meta or {})
        self.path = path
        self.top_n = int(top_n)
        self.max_age_days = int(max_age_days)
        self.error = error
        self.psl_rules, self.psl_wild = load_private_suffixes(psl_path or BUNDLED_PSL)
        self.shared_hosts, self.shared_domains = load_shared_hosts(shared_path or SHARED_HOSTS)

    # ---------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: Path, *, top_n: int = 60_000, max_age_days: int = 45,
             shared_path: Path | None = None) -> "Reputation":
        """Missing list → empty (status LIST_MISSING). Corrupt list → empty + error (fail closed)."""
        path = Path(path)
        psl = path.parent / "public_suffix_list.dat"
        psl_path = psl if psl.exists() else BUNDLED_PSL
        if not path.exists():
            return cls(path=path, top_n=top_n, max_age_days=max_age_days, psl_path=psl_path, shared_path=shared_path)
        try:
            ranks = read_ranks(path, top_n)
            meta_path = path.with_suffix(".json")
            meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
            if not _parse_ts(meta.get("retrieved_at")):
                raise ValueError(f"{meta_path}: missing or invalid retrieved_at")
            return cls(ranks, meta=meta, path=path, top_n=top_n, max_age_days=max_age_days,
                       psl_path=psl_path, shared_path=shared_path)
        except Exception as exc:  # noqa: BLE001 — any problem: nothing is reputable
            logger.error("Reputation list %s could not be loaded (%s); no site is SAFE by reputation", path, exc)
            return cls(path=path, top_n=top_n, max_age_days=max_age_days, psl_path=psl_path,
                       shared_path=shared_path, error=str(exc)[:300])

    @property
    def version(self) -> str:
        if not self.ranks:
            return "rep_none"
        return f"tranco-{self.meta.get('list_id') or 'unknown'}@{str(self.meta.get('retrieved_at'))[:19]}/top{self.top_n}"

    @property
    def retrieved_at(self) -> datetime | None:
        return _parse_ts(self.meta.get("retrieved_at"))

    def stale(self, now: datetime | None = None) -> bool:
        ts = self.retrieved_at
        return ts is None or (now or _now()) - ts > timedelta(days=self.max_age_days)

    def needs_refresh(self, refresh_days: int, now: datetime | None = None) -> bool:
        ts = self.retrieved_at
        return not self.ranks or ts is None or (now or _now()) - ts > timedelta(days=refresh_days)

    def status(self, now: datetime | None = None) -> dict:
        return {"loaded": bool(self.ranks), "version": self.version, "domains": len(self.ranks),
                "top_n": self.top_n, "list_id": self.meta.get("list_id"),
                "retrieved_at": self.meta.get("retrieved_at"), "stale": bool(self.ranks) and self.stale(now),
                "error": self.error, "path": str(self.path) if self.path else None}

    # ---------------------------------------------------------------- lookup

    def shared_platform(self, host: str) -> str | None:
        """→ reason when the host is on a platform where anyone can publish, else None."""
        if host in self.shared_hosts:
            return f"{host} hosts content that anyone can publish (forms / files / pages)"
        labels = host.split(".")
        for i in range(len(labels)):
            parent = ".".join(labels[i:])
            if parent in self.shared_domains:
                return f"{parent} is a link-shortener / file-share / site-builder service"
            if i >= 1 and (parent in self.psl_rules or parent in self.psl_wild):
                return f"{host} is a user sub-domain on the shared platform {parent}"
        return None

    def lookup(self, host: str, now: datetime | None = None) -> ReputationResult:
        host = ascii_host(host)
        common = {"host": host, "list_id": self.meta.get("list_id"),
                  "list_date": str(self.meta.get("retrieved_at") or "")[:10] or None}
        if not self.ranks:
            reason = ("reputation list invalid — " + self.error) if self.error else \
                "no reputation list downloaded yet (make reputation-update)"
            return ReputationResult(LIST_INVALID if self.error else LIST_MISSING, reason=reason, **common)
        if self.stale(now):
            return ReputationResult(LIST_STALE, reason=f"reputation list is older than {self.max_age_days} days", **common)
        shared = self.shared_platform(host)
        if shared:
            return ReputationResult(SHARED_HOST, reason=shared, **common)
        labels = host.split(".")
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            rank = self.ranks.get(parent)
            if rank is not None:
                return ReputationResult(
                    REPUTABLE, domain=parent, rank=rank,
                    reason=f"widely used website: {parent} is ranked #{rank:,} worldwide (Tranco list "
                           f"{self.meta.get('list_id') or '?'}, {common['list_date']}) — not a government source",
                    **common)
        return ReputationResult(NOT_RANKED, reason=f"not in the top {self.top_n:,} sites", **common)


def read_ranks(path: Path, top_n: int) -> dict[str, int]:
    ranks: dict[str, int] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 2 or not row[0].strip().isdigit():
                continue
            rank, domain = int(row[0]), ascii_host(row[1])
            if rank > top_n:
                break
            if _DOMAIN.match(domain):
                ranks.setdefault(domain, rank)
    if not ranks:
        raise ValueError(f"{path}: no ranked domains")
    return ranks


# ------------------------------------------------------------------ download (network)


def _get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Daggers-reputation-update/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https URLs
        return resp.read()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def update(path: Path, *, top_n: int = 60_000, timeout: float = 60.0, fetch=_get) -> dict:
    """Download the latest Tranco list (+ Public Suffix List), validate, and write atomically.

    Keeps only the top `top_n` rows. Raises on any problem and leaves the current files untouched.
    """
    path = Path(path)
    list_id = fetch(TRANCO_ID_URL, timeout).decode("utf-8", "replace").strip()
    if not re.fullmatch(r"[A-Z0-9]{3,12}", list_id):
        raise ValueError(f"unexpected Tranco list id {list_id[:40]!r}")
    blob = fetch(TRANCO_LIST_URL, timeout)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        name = next((n for n in zf.namelist() if n.endswith(".csv")), None)
        if not name:
            raise ValueError("Tranco archive contains no CSV")
        text = zf.read(name).decode("utf-8", "replace")
    out = io.StringIO()
    rows = 0
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[0].strip().isdigit():
            if int(row[0]) > top_n:
                break
            domain = ascii_host(row[1])
            if _DOMAIN.match(domain):
                out.write(f"{int(row[0])},{domain}\n")
                rows += 1
    if rows < min(MIN_ROWS, top_n):
        raise ValueError(f"Tranco list too short ({rows} rows) — not installed")
    psl = fetch(PSL_URL, timeout)
    if b"===BEGIN PRIVATE DOMAINS===" not in psl:
        raise ValueError("Public Suffix List download is invalid — not installed")
    meta = {"source": "Tranco (https://tranco-list.eu)", "list_id": list_id,
            "list_url": f"https://tranco-list.eu/list/{list_id}/1000000", "top_n": top_n, "rows": rows,
            "retrieved_at": _now().replace(microsecond=0).isoformat(),
            "public_suffix_list": PSL_URL}
    _atomic_write(path.parent / "public_suffix_list.dat", psl)
    _atomic_write(path, out.getvalue().encode("utf-8"))
    _atomic_write(path.with_suffix(".json"), json.dumps(meta, indent=2).encode("utf-8"))
    return meta


def main(argv: list[str] | None = None) -> int:
    import argparse

    from ..config import Settings

    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description="Download / inspect the site-reputation list (Tranco).")
    parser.add_argument("command", choices=["update", "status", "lookup"])
    parser.add_argument("hosts", nargs="*")
    args = parser.parse_args(argv)
    path = settings.reputation_list_path
    if args.command == "update":
        meta = update(path, top_n=settings.reputation_top_n)
        print(f"installed Tranco list {meta['list_id']} — {meta['rows']} domains → {path}")
        return 0
    rep = Reputation.load(path, top_n=settings.reputation_top_n, max_age_days=settings.reputation_max_age_days)
    if args.command == "status":
        print(json.dumps(rep.status(), indent=2))
        return 0
    for host in args.hosts:
        print(json.dumps(rep.lookup(host).as_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
