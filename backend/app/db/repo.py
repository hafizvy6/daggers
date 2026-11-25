from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..config import Settings
from ..core import homograph

SCHEMA_PATH = Path(__file__).resolve().with_name("schema.sql")

FINDING_ORDER = (
    "id",
    "domain",
    "verdict",
    "score",
    "reasons",
    "cert_issued",
    "first_seen",
    "source",
    "clone",
    "evidence_url",
    "gallery_match",
    "is_case_file",
)
REPORT_ORDER = (
    "id",
    "finding_id",
    "evidence",
    "status",
    "auto",
    "filed_at",
    "blocked_hits",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_finding(value: Mapping[str, Any]) -> dict:
    reasons = value.get("reasons") or []
    if isinstance(reasons, str):
        try:
            reasons = json.loads(reasons)
        except json.JSONDecodeError:
            reasons = [reasons]
    clone_value = float(value.get("clone") or 0.0)
    clone: int | float = int(clone_value) if clone_value.is_integer() else clone_value
    return {
        "id": int(value.get("id") or 0),
        "domain": str(value.get("domain") or ""),
        "verdict": str(value.get("verdict") or "UNKNOWN"),
        "score": float(value.get("score") or 0.0),
        "reasons": [str(reason) for reason in reasons],
        "cert_issued": value.get("cert_issued"),
        "first_seen": str(value.get("first_seen") or ""),
        "source": str(value.get("source") or ""),
        "clone": clone,
        "evidence_url": value.get("evidence_url"),
        "gallery_match": value.get("gallery_match"),
        "is_case_file": bool(value.get("is_case_file")),
    }


# Additive finding fields produced by the WS2 trust policy and investigations.
FINDING_DETAIL_KEYS = (
    "tag", "manual_review", "domain_auth", "gov_verification", "trust_reasons",
    "scam_type", "signals", "submitted_url", "investigator", "policy_version",
    "registrable_domain", "created_at",
    # live Checker
    "input_type", "submitted_input", "normalized_url", "analyzed_url", "urls", "scanned_at",
    "scan_status", "checks", "precautions", "redactions", "homograph", "normalized", "risk_score",
    "engine_version", "maliciousness", "verdict_history", "reputation_version",
    "reason_codes", "final_domain_auth", "evidence", "live_evidence",
)


def finding_with_detail(value: Mapping[str, Any], detail: Mapping[str, Any] | str | None) -> dict:
    """C1 finding + integration detail (tag, authentication, verification evidence)."""
    base = canonical_finding(value)
    if isinstance(detail, str):
        try:
            detail = json.loads(detail or "{}")
        except json.JSONDecodeError:
            detail = {}
    for key in FINDING_DETAIL_KEYS:
        if detail and key in detail:
            base[key] = detail[key]
    return base


def canonical_report(value: Mapping[str, Any]) -> dict:
    evidence = value.get("evidence") or {}
    if isinstance(evidence, str):
        evidence = json.loads(evidence)
    return {
        "id": int(value.get("id") or 0),
        "finding_id": int(value.get("finding_id") or 0),
        "evidence": canonical_finding(evidence),
        "status": str(value.get("status") or "QUEUED"),
        "auto": bool(value.get("auto")),
        "filed_at": value.get("filed_at"),
        "blocked_hits": int(value.get("blocked_hits") or 0),
    }


def report_with_ai(row: Mapping[str, Any]) -> dict:
    report = canonical_report(row)
    evidence = row.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {}
    if isinstance(evidence, Mapping):
        for key in ("tag", "evidence_id", "verification_status"):
            if key in evidence:
                report["evidence"][key] = evidence[key]
    report["domain"] = report["evidence"]["domain"]
    ai = row.get("ai") if hasattr(row, "get") else None
    report["ai"] = json.loads(ai) if isinstance(ai, str) and ai else None
    return report


class Repository:
    """All SQL lives here. Live data only: there is no seed, fixture or demo data."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path = settings.db_path
        self.evidence_dir = settings.evidence_dir
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ boot

    def initialize(self) -> bool:
        missing = not self.db_path.exists()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.settings.gallery_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
                self._migrate()
                self._conn.commit()
        return missing

    MIGRATIONS = (
        ("sweep_results", "detail", "ALTER TABLE sweep_results ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'"),
        ("findings", "detail", "ALTER TABLE findings ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'"),
        ("reports", "ai", "ALTER TABLE reports ADD COLUMN ai TEXT"),
        ("sweep_runs", "query_id", "ALTER TABLE sweep_runs ADD COLUMN query_id TEXT"),
        ("sweep_runs", "state", "ALTER TABLE sweep_runs ADD COLUMN state TEXT NOT NULL DEFAULT '{}'"),
    )

    def _migrate(self) -> None:
        """Additive, idempotent column migrations (never drops or rewrites data)."""
        assert self._conn is not None
        for table, column, statement in self.MIGRATIONS:
            columns = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                self._conn.execute(statement)
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '3') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        assert self._conn is not None
        return self._conn

    # ------------------------------------------------------------- meta + domains

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._lock, self.conn:
            row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_meta(self, key: str, value: object) -> None:
        serialized = value if isinstance(value, str) else _json(value)
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, serialized),
            )

    def upsert_domain(
        self,
        domain: str,
        *,
        source: str | None = None,
        cert_names: Iterable[str] | None = None,
        first_seen: str | None = None,
        rdap_created: str | None = None,
        rdap_registrar: str | None = None,
        dns_a: Iterable[str] | None = None,
        tls_issued: str | None = None,
        tls_issuer: str | None = None,
        favicon_hash: str | None = None,
        enqueued: bool | None = None,
    ) -> int:
        clean = str(domain).strip().rstrip(".").lower()
        seen = first_seen or utc_now()
        certs = _json(list(cert_names)) if cert_names is not None else None
        addresses = _json(list(dns_a)) if dns_a is not None else None
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO domains("
                "domain, source, cert_names, first_seen, rdap_created, rdap_registrar, "
                "dns_a, tls_issued, tls_issuer, favicon_hash, enqueued"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 0))",
                (
                    clean,
                    source,
                    certs,
                    seen,
                    rdap_created,
                    rdap_registrar,
                    addresses,
                    tls_issued,
                    tls_issuer,
                    favicon_hash,
                    1 if enqueued else None,
                ),
            )
            self.conn.execute(
                "UPDATE domains SET "
                "source = COALESCE(source, ?), cert_names = COALESCE(cert_names, ?), "
                "rdap_created = COALESCE(rdap_created, ?), rdap_registrar = COALESCE(rdap_registrar, ?), "
                "dns_a = COALESCE(dns_a, ?), tls_issued = COALESCE(tls_issued, ?), "
                "tls_issuer = COALESCE(tls_issuer, ?), favicon_hash = COALESCE(favicon_hash, ?), "
                "enqueued = CASE WHEN ? IS NULL THEN enqueued ELSE MAX(enqueued, ?) END "
                "WHERE domain = ?",
                (
                    source,
                    certs,
                    rdap_created,
                    rdap_registrar,
                    addresses,
                    tls_issued,
                    tls_issuer,
                    favicon_hash,
                    1 if enqueued is not None else None,
                    1 if enqueued else 0,
                    clean,
                ),
            )
            row = self.conn.execute("SELECT id FROM domains WHERE domain = ?", (clean,)).fetchone()
        return int(row["id"])

    def get_domain(self, domain: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM domains WHERE domain = ?", (domain.lower(),)).fetchone()
        return dict(row) if row else None

    def unprocessed_domains(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM domains WHERE enqueued = 0 ORDER BY first_seen ASC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_enqueued(self, domain: str) -> None:
        with self._lock, self.conn:
            self.conn.execute("UPDATE domains SET enqueued = 1 WHERE domain = ?", (domain.lower(),))

    # ---------------------------------------------------------------- findings

    def _row_to_finding(self, row: sqlite3.Row) -> dict:
        keys = row.keys()
        detail = dict(json.loads(row["detail"] or "{}")) if "detail" in keys else {}
        if "created_at" in keys and row["created_at"]:
            detail.setdefault("created_at", row["created_at"])
        return finding_with_detail(
            {
                "id": row["id"],
                "domain": row["domain"],
                "verdict": row["verdict"],
                "score": row["score"],
                "reasons": row["reasons"],
                "cert_issued": row["cert_issued"],
                "first_seen": row["first_seen"],
                "source": row["source"],
                "clone": row["clone"] or 0,
                "evidence_url": row["evidence_url"],
                "gallery_match": row["gallery_match"],
                "is_case_file": row["is_case_file"],
            },
            detail,
        )

    def get_finding(self, finding_id: int, mode: str = "live") -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, "
                "COALESCE(json_extract(f.detail, '$.source'), d.source) AS source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file, f.detail, f.created_at "
                "FROM findings f JOIN domains d ON d.id = f.domain_id WHERE f.id = ?",
                (int(finding_id),),
            ).fetchone()
        return self._row_to_finding(row) if row else None

    # Portal-only findings: officer investigations and public Checker submissions (which may
    # contain a member of the public's message). Never in the public feed, stream or Guard.
    RESTRICTED_SOURCES = ("investigation", "checker")

    def get_findings(self, limit: int = 50, mode: str = "live", include_restricted: bool = False) -> list[dict]:
        """Newest findings. Restricted (portal investigation) findings are excluded unless asked."""
        limit = max(1, min(int(limit), 200))
        where = "" if include_restricted else (
            "WHERE COALESCE(json_extract(f.detail, '$.source'), d.source, '') NOT IN ('investigation', 'checker') "
        )
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, "
                "COALESCE(json_extract(f.detail, '$.source'), d.source) AS source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file, f.detail, f.created_at "
                "FROM findings f JOIN domains d ON d.id = f.domain_id "
                + where +
                "ORDER BY f.created_at DESC, f.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def insert_finding(
        self,
        *,
        domain: str,
        score: float,
        verdict: str,
        reasons: Iterable[str],
        l1_detail: Mapping[str, float] | None = None,
        source: str | None = None,
        first_seen: str | None = None,
        cert_issued: str | None = None,
        rendered: bool = False,
        evidence_path: str | None = None,
        gallery_match: str | None = None,
        clone_score: float | None = None,
        created_at: str | None = None,
        is_case_file: bool = False,
        finding_id: int | None = None,
        enqueued: bool | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict:
        domain_id = self.upsert_domain(
            domain,
            source=source,
            first_seen=first_seen,
            tls_issued=cert_issued,
            enqueued=enqueued,
        )
        values = (
            domain_id,
            float(score),
            verdict,
            _json(list(reasons)),
            _json(dict(l1_detail or {})),
            1 if rendered else 0,
            evidence_path,
            gallery_match,
            float(clone_score) if clone_score is not None else None,
            created_at or utc_now(),
            1 if is_case_file else 0,
            _json(dict(detail or {})),
        )
        with self._lock, self.conn:
            if finding_id is None:
                cursor = self.conn.execute(
                    "INSERT INTO findings("
                    "domain_id, score, verdict, reasons, l1_detail, rendered, evidence_path, "
                    "gallery_match, clone_score, created_at, is_case_file, detail"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
                new_id = int(cursor.lastrowid)
            else:
                self.conn.execute(
                    "INSERT OR IGNORE INTO findings("
                    "id, domain_id, score, verdict, reasons, l1_detail, rendered, evidence_path, "
                    "gallery_match, clone_score, created_at, is_case_file, detail"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (int(finding_id), *values),
                )
                new_id = int(finding_id)
        return self.get_finding(new_id, "live") or canonical_finding({"id": new_id, "domain": domain})

    def set_finding_evidence(self, finding_id: int, evidence_url: str) -> dict | None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE findings SET evidence_path = ?, rendered = 1 WHERE id = ?",
                (evidence_url, int(finding_id)),
            )
        return self.get_finding(finding_id, "live")

    def update_finding_analysis(
        self,
        finding_id: int,
        *,
        score: float,
        verdict: str,
        reasons: Iterable[str],
        l1_detail: Mapping[str, float],
        clone_score: float | None = None,
        gallery_match: str | None = None,
        evidence_path: str | None = None,
        rendered: bool | None = None,
    ) -> dict | None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE findings SET score = ?, verdict = ?, reasons = ?, l1_detail = ?, "
                "clone_score = COALESCE(?, clone_score), gallery_match = COALESCE(?, gallery_match), "
                "evidence_path = COALESCE(?, evidence_path), rendered = COALESCE(?, rendered) "
                "WHERE id = ?",
                (
                    float(score),
                    verdict,
                    _json(list(reasons)),
                    _json(dict(l1_detail)),
                    clone_score,
                    gallery_match,
                    evidence_path,
                    1 if rendered else None,
                    int(finding_id),
                ),
            )
        return self.get_finding(finding_id, "live")

    def evidence_path(self, finding_id: int, mode: str = "live") -> Path | None:
        finding = self.get_finding(int(finding_id), mode)
        if not finding or not finding["evidence_url"]:
            return None
        url = str(finding["evidence_url"])
        return self.evidence_dir / Path(url).name

    def ensure_evidence_file(self, finding_id: int, mode: str = "live") -> Path | None:
        finding = self.get_finding(int(finding_id), mode)
        if finding is None:
            return None
        destination = self.evidence_path(int(finding_id), mode)
        if destination is None:
            return None
        if destination.exists() and destination.stat().st_size > 0:
            return destination
        return None  # real evidence only: a missing render is a 404, never a generated stand-in

    def find_evidence_url(self, domain: str, mode: str = "live") -> str | None:
        def same(left: str, right: str) -> bool:
            left_forms = homograph.host_forms(left)
            right_forms = homograph.host_forms(right)
            left_set = {str(left_forms["unicode_host"]), str(left_forms["punycode_host"])}
            right_set = {str(right_forms["unicode_host"]), str(right_forms["punycode_host"])}
            return bool(left_set & right_set)

        with self._lock:
            rows = self.conn.execute(
                "SELECT d.domain, f.evidence_path FROM findings f JOIN domains d ON d.id = f.domain_id "
                "WHERE f.evidence_path IS NOT NULL ORDER BY f.id DESC LIMIT 200"
            ).fetchall()
        for row in rows:
            if same(str(domain), str(row["domain"])):
                return str(row["evidence_path"])
        return None

    # ------------------------------------------------------------------ guard

    def get_guard_rows(self, mode: str = "live", guard_block_misleading: bool = False) -> list[dict]:
        verdicts = ["MALICIOUS", "MISLEADING"] if guard_block_misleading else ["MALICIOUS"]
        timestamps: dict[int, str] = {}
        placeholders = ",".join("?" for _ in verdicts)
        with self._lock:
            rows = self.conn.execute(
                f"SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                f"COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, d.source, "
                f"COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                f"f.gallery_match, f.is_case_file, f.created_at "
                f"FROM findings f JOIN domains d ON d.id = f.domain_id "
                f"WHERE f.verdict IN ({placeholders}) "
                f"AND COALESCE(json_extract(f.detail, '$.source'), '') != 'checker' AND f.id = ("
                f"SELECT MAX(f2.id) FROM findings f2 WHERE f2.domain_id = f.domain_id "
                f"AND f2.verdict IN ({placeholders}) "
                f"AND COALESCE(json_extract(f2.detail, '$.source'), '') != 'checker') "
                f"ORDER BY f.created_at DESC, f.id DESC",
                (*verdicts, *verdicts),
            ).fetchall()
        findings = [self._row_to_finding(row) for row in rows]
        timestamps = {int(row["id"]): str(row["created_at"]) for row in rows}
        seen: set[str] = set()
        guard_rows: list[dict] = []
        for finding in findings:
            domain = finding["domain"]
            if domain in seen:
                continue
            seen.add(domain)
            punycode = str(homograph.host_forms(domain)["punycode_host"])
            guard_rows.append(
                {
                    "domain": punycode,
                    "verdict": finding["verdict"],
                    "reason": (finding["reasons"] or ["confirmed by deterministic evidence"])[0],
                    "flagged_at": timestamps.get(finding["id"], finding["first_seen"]),
                }
            )
        return guard_rows

    def guard_stats(self, mode: str = "live", guard_block_misleading: bool = False) -> dict:
        rows = self.get_guard_rows(mode, guard_block_misleading)
        with self._lock:
            hit_row = self.conn.execute("SELECT COALESCE(SUM(count), 0) AS total FROM guard_hits").fetchone()
        total_hits = int(hit_row["total"]) if hit_row else 0
        return {
            "blocked_domains": len(rows),
            "blocked_hits": total_hits,
            # Guard view aliases; the original keys remain authoritative.
            "blocked_today": total_hits,
            "feed_size": len(rows),
            "mode": "live",
        }

    # ---------------------------------------------------------------- Guard (live block list)

    def guard_candidates(self, verdicts: Iterable[str], limit: int = 5000) -> list[dict]:
        """The LATEST finding of every domain whose latest engine verdict is in `verdicts` (any source)."""
        verdicts = list(verdicts)
        placeholders = ",".join("?" for _ in verdicts)
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, "
                "COALESCE(json_extract(f.detail, '$.source'), d.source) AS source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file, f.detail, f.created_at "
                "FROM findings f JOIN domains d ON d.id = f.domain_id "
                f"WHERE f.verdict IN ({placeholders}) AND f.id = "
                "(SELECT MAX(f2.id) FROM findings f2 WHERE f2.domain_id = f.domain_id) "
                "ORDER BY f.id DESC LIMIT ?", (*verdicts, int(limit))).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def guard_list_rows(self, active_only: bool = True) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT domain, active, source, finding_id, tag, verdict, score, reason, listed_at, updated_at, "
                "delisted_reason FROM guard_blocklist" + (" WHERE active = 1" if active_only else "")
                + " ORDER BY listed_at DESC, domain").fetchall()
        return [dict(r) for r in rows]

    def guard_get(self, domain: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT domain, active, source, finding_id, tag, verdict, score, reason, listed_at, updated_at, "
                "delisted_reason FROM guard_blocklist WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None

    def guard_upsert(self, entry: Mapping[str, Any]) -> bool:
        """Insert or refresh a listed domain. → True when it was not active before (newly listed)."""
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute("SELECT active, listed_at FROM guard_blocklist WHERE domain = ?",
                                    (entry["domain"],)).fetchone()
            new = row is None or not row["active"]
            listed_at = now if new else row["listed_at"]
            self.conn.execute(
                "INSERT INTO guard_blocklist(domain, active, source, finding_id, tag, verdict, score, reason, "
                "listed_at, updated_at, delisted_reason) VALUES(?, 1, ?, ?, ?, ?, ?, ?, ?, ?, NULL) "
                "ON CONFLICT(domain) DO UPDATE SET active = 1, source = excluded.source, "
                "finding_id = excluded.finding_id, tag = excluded.tag, verdict = excluded.verdict, "
                "score = excluded.score, reason = excluded.reason, listed_at = excluded.listed_at, "
                "updated_at = excluded.updated_at, delisted_reason = NULL",
                (entry["domain"], entry["source"], entry.get("finding_id"), entry["tag"], entry["verdict"],
                 float(entry.get("score") or 0.0), str(entry.get("reason") or "")[:300], listed_at, now))
            if new:
                self.conn.execute("INSERT INTO guard_events(kind, domain, source, at) VALUES('listed', ?, ?, ?)",
                                  (entry["domain"], entry["source"], now))
        return new

    def guard_delist(self, domain: str, reason: str) -> bool:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE guard_blocklist SET active = 0, delisted_reason = ?, updated_at = ? "
                "WHERE domain = ? AND active = 1", (reason[:200], now, domain))
            if cur.rowcount:
                self.conn.execute("INSERT INTO guard_events(kind, domain, detail, at) VALUES('delisted', ?, ?, ?)",
                                  (domain, _json({"reason": reason[:200]}), now))
        return bool(cur.rowcount)

    def guard_record_block(self, domain: str, day: str) -> tuple[int, int]:
        """A real block (DoH answer / verdict-page hit). No client data is stored. → (today, total)."""
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute("INSERT INTO guard_daily(day, hits) VALUES(?, 1) "
                              "ON CONFLICT(day) DO UPDATE SET hits = hits + 1", (day,))
            self.conn.execute(
                "INSERT INTO guard_hits(domain, count, updated_at) VALUES(?, 1, ?) "
                "ON CONFLICT(domain) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at",
                (domain.lower(), now))
            today = self.conn.execute("SELECT hits FROM guard_daily WHERE day = ?", (day,)).fetchone()["hits"]
            total = self.conn.execute("SELECT COALESCE(SUM(hits), 0) AS n FROM guard_daily").fetchone()["n"]
        return int(today), int(total)

    def guard_block_counts(self, day: str) -> tuple[int, int]:
        with self._lock:
            row = self.conn.execute("SELECT hits FROM guard_daily WHERE day = ?", (day,)).fetchone()
            total = self.conn.execute("SELECT COALESCE(SUM(hits), 0) AS n FROM guard_daily").fetchone()["n"]
        return (int(row["hits"]) if row else 0), int(total)

    def guard_log_event(self, kind: str, detail: Mapping[str, Any]) -> None:
        with self._lock, self.conn:
            self.conn.execute("INSERT INTO guard_events(kind, detail, at) VALUES(?, ?, ?)",
                              (kind, _json(dict(detail)), utc_now()))
            self.conn.execute("DELETE FROM guard_events WHERE id NOT IN "
                              "(SELECT id FROM guard_events ORDER BY id DESC LIMIT 2000)")

    def guard_last_event(self, kind: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT detail, at FROM guard_events WHERE kind = ? ORDER BY id DESC LIMIT 1",
                                    (kind,)).fetchone()
        return {"at": row["at"], **json.loads(row["detail"] or "{}")} if row else None

    def guard_pushed(self, provider: str) -> set[str]:
        with self._lock:
            rows = self.conn.execute("SELECT domain FROM guard_pushed WHERE provider = ?", (provider,)).fetchall()
        return {r["domain"] for r in rows}

    def guard_mark_pushed(self, provider: str, added: Iterable[str], removed: Iterable[str]) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.executemany("INSERT OR REPLACE INTO guard_pushed(provider, domain, pushed_at) VALUES(?, ?, ?)",
                                  [(provider, d, now) for d in added])
            self.conn.executemany("DELETE FROM guard_pushed WHERE provider = ? AND domain = ?",
                                  [(provider, d) for d in removed])

    def record_guard_hit(self, domain: str) -> int:
        clean = str(domain).lower()
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO guard_hits(domain, count, updated_at) VALUES(?, 1, ?) "
                "ON CONFLICT(domain) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at",
                (clean, now),
            )
            row = self.conn.execute("SELECT count FROM guard_hits WHERE domain = ?", (clean,)).fetchone()
        return int(row["count"])

    # ---------------------------------------------------------------- reports

    def _row_to_report(self, row: sqlite3.Row) -> dict:
        return report_with_ai(dict(row))

    def insert_report(
        self,
        *,
        finding_id: int,
        evidence: Mapping[str, Any],
        status: str,
        auto: bool,
        filed_at: str | None,
        blocked_hits: int = 0,
        report_id: int | None = None,
    ) -> dict:
        from ..reports.builder import validate_zero_pii

        clean_evidence = canonical_finding(evidence)
        # Zero-PII additive fields only: the final tag and a pointer to verification evidence.
        for key in ("tag", "evidence_id", "verification_status"):
            if evidence.get(key) is not None:
                clean_evidence[key] = str(evidence[key])
        validate_zero_pii(clean_evidence)
        values = (
            int(finding_id),
            status,
            1 if auto else 0,
            _json(clean_evidence),
            filed_at,
            int(blocked_hits),
            utc_now(),
        )
        with self._lock, self.conn:
            if report_id is None:
                self.conn.execute(
                    "INSERT OR IGNORE INTO reports("
                    "finding_id, status, auto, evidence, filed_at, blocked_hits, created_at"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
            else:
                self.conn.execute(
                    "INSERT OR IGNORE INTO reports("
                    "id, finding_id, status, auto, evidence, filed_at, blocked_hits, created_at"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (int(report_id), *values),
                )
            row = self.conn.execute("SELECT * FROM reports WHERE finding_id = ?", (int(finding_id),)).fetchone()
        return self._row_to_report(row)

    def get_report(self, report_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM reports WHERE id = ?", (int(report_id),)).fetchone()
        return self._row_to_report(row) if row else None

    def list_reports(self, status: str | None = None, limit: int = 50) -> list[dict]:
        with self._lock:
            if status:
                rows = self.conn.execute(
                    "SELECT * FROM reports WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status, max(1, int(limit))),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM reports ORDER BY id DESC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
        return [self._row_to_report(row) for row in rows]

    def save_report_ai(self, report_id: int, payload: Mapping[str, Any]) -> None:
        keep = {k: payload.get(k) for k in ("summary_en", "summary_ar", "provider", "fallback", "grounding")}
        keep["written_at"] = utc_now()
        with self._lock, self.conn:
            self.conn.execute("UPDATE reports SET ai = ? WHERE id = ?", (_json(keep), int(report_id)))

    def report_for_finding(self, finding_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM reports WHERE finding_id = ?", (int(finding_id),)).fetchone()
        return self._row_to_report(row) if row else None

    def set_report_status(self, report_id: int, status: str, filed_at: str | None = None) -> dict | None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE reports SET status = ?, filed_at = COALESCE(?, filed_at) WHERE id = ?",
                (status, filed_at, int(report_id)),
            )
        return self.get_report(int(report_id))

    # -------------------------------------------------------------- feed labels

    def upsert_feed_labels(self, domains: Iterable[str], source: str) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO feed_labels(domain, source, confirmed, updated_at) VALUES(?, ?, 1, ?) "
                "ON CONFLICT(domain) DO UPDATE SET source = excluded.source, confirmed = 1, "
                "updated_at = excluded.updated_at",
                [(str(domain).lower(), source, now) for domain in domains],
            )

    def upsert_feed_urls(self, rows: Iterable[tuple[str, str]], source: str) -> None:
        """rows = (url_key, host). See intel.feeds.url_key()."""
        now = utc_now()
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO feed_urls(url_key, host, source, updated_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(url_key) DO UPDATE SET source = excluded.source, updated_at = excluded.updated_at",
                [(key[:2048], host.lower(), source, now) for key, host in rows],
            )

    def feed_lookup(self, url_key: str, host: str, site: str) -> dict:
        """Exact-URL listing vs host listing (feed_urls host, or a legacy domain label for the site)."""
        host, site = host.lower(), site.lower()
        with self._lock:
            url_row = self.conn.execute("SELECT source, updated_at FROM feed_urls WHERE url_key = ?",
                                        (url_key[:2048],)).fetchone()
            host_rows = self.conn.execute(
                "SELECT source, MAX(updated_at) AS updated_at, COUNT(*) AS n FROM feed_urls WHERE host = ? "
                "GROUP BY source", (host,)).fetchall()
            label = self.conn.execute("SELECT source, updated_at FROM feed_labels WHERE domain IN (?, ?) "
                                      "AND confirmed = 1", (host, site)).fetchone()
        sources = sorted({r["source"] for r in host_rows} | ({label["source"]} if label else set())
                         | ({url_row["source"]} if url_row else set()))
        return {"url_listed": url_row is not None, "host_listed": bool(host_rows) or label is not None,
                "host_listing_count": sum(int(r["n"]) for r in host_rows), "sources": sources}

    def feed_freshness(self) -> str | None:
        """When feed data was last refreshed (latest row), or None when no feed data exists."""
        with self._lock:
            row = self.conn.execute(
                "SELECT MAX(t) AS t FROM (SELECT MAX(updated_at) AS t FROM feed_urls "
                "UNION ALL SELECT MAX(updated_at) FROM feed_labels)").fetchone()
        return row["t"] if row and row["t"] else None

    def confirmed_domains(self) -> set[str]:
        with self._lock:
            rows = self.conn.execute("SELECT domain FROM feed_labels WHERE confirmed = 1").fetchall()
        return {str(row["domain"]) for row in rows}

    def findings_by_source(self, source_prefix: str, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, "
                "COALESCE(json_extract(f.detail, '$.source'), d.source) AS source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file, f.detail, f.created_at "
                "FROM findings f JOIN domains d ON d.id = f.domain_id "
                "WHERE COALESCE(json_extract(f.detail, '$.source'), d.source) LIKE ? "
                "ORDER BY f.id DESC LIMIT ?",
                (f"{source_prefix}%", max(1, min(int(limit), 500))),
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    # ------------------------------------------------------------------ live Checker

    def check_request_finding(self, request_id: str) -> int | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT finding_id FROM check_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return int(row["finding_id"]) if row else None

    def recent_check_finding(self, content_hash: str, client_hash: str, since: str) -> int | None:
        """Same input from the same client within the window → the existing finding."""
        with self._lock:
            row = self.conn.execute(
                "SELECT finding_id FROM check_requests WHERE content_hash = ? AND client_hash = ? "
                "AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
                (content_hash, client_hash, since),
            ).fetchone()
        return int(row["finding_id"]) if row else None

    def insert_check_finding(
        self,
        *,
        request_id: str,
        content_hash: str,
        client_hash: str,
        domain: str,
        score: float,
        verdict: str,
        reasons: Iterable[str],
        l1_detail: Mapping[str, float],
        detail: Mapping[str, Any],
        created_at: str,
    ) -> tuple[int, bool]:
        """Atomically store a Checker finding + its request key. → (finding_id, created)."""
        with self._lock, self.conn:
            existing = self.conn.execute(
                "SELECT finding_id FROM check_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if existing:
                return int(existing["finding_id"]), False
            clean = str(domain).strip().rstrip(".").lower()
            self.conn.execute(
                "INSERT OR IGNORE INTO domains(domain, source, first_seen, enqueued) VALUES(?, 'checker', ?, 1)",
                (clean, created_at),
            )
            domain_id = int(self.conn.execute("SELECT id FROM domains WHERE domain = ?", (clean,)).fetchone()["id"])
            cursor = self.conn.execute(
                "INSERT INTO findings(domain_id, score, verdict, reasons, l1_detail, rendered, created_at, "
                "is_case_file, detail) VALUES(?, ?, ?, ?, ?, 0, ?, 0, ?)",
                (domain_id, float(score), verdict, _json(list(reasons)), _json(dict(l1_detail)),
                 created_at, _json(dict(detail))),
            )
            finding_id = int(cursor.lastrowid)
            self.conn.execute(
                "INSERT INTO check_requests(request_id, finding_id, content_hash, client_hash, created_at) "
                "VALUES(?, ?, ?, ?, ?)",
                (request_id, finding_id, content_hash, client_hash, created_at),
            )
        return finding_id, True

    def search_findings(
        self,
        *,
        q: str | None = None,
        source: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        scan_limit: int = 2000,
    ) -> list[dict]:
        """Portal search (SQL part). Tag / input-type filters are applied by the runtime,
        because radar findings get their tag from the trust policy at read time."""
        clauses: list[str] = []
        params: list[Any] = []
        if source:
            clauses.append("COALESCE(json_extract(f.detail, '$.source'), d.source, '') LIKE ?")
            params.append(f"{source}%")
        if date_from:
            clauses.append("f.created_at >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("f.created_at < ?")
            params.append(date_to)
        if q:
            like = f"%{q.lower()}%"
            clauses.append(
                "(lower(d.domain) LIKE ? OR lower(COALESCE(json_extract(f.detail, '$.submitted_input'), '')) LIKE ? "
                "OR lower(COALESCE(json_extract(f.detail, '$.submitted_url'), '')) LIKE ? "
                "OR lower(f.reasons) LIKE ? OR CAST(f.id AS TEXT) = ?)"
            )
            params.extend([like, like, like, like, q.strip().lstrip("#")])
        where = ("WHERE " + " AND ".join(clauses) + " ") if clauses else ""
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, "
                "COALESCE(json_extract(f.detail, '$.source'), d.source) AS source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file, f.detail, f.created_at "
                "FROM findings f JOIN domains d ON d.id = f.domain_id "
                + where +
                "ORDER BY f.created_at DESC, f.id DESC LIMIT ?",
                (*params, max(1, min(int(scan_limit), 5000))),
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def findings_with_stale_policy(self, registry_version: str, policy_version: str,
                                   reputation_version: str | None = None) -> list[int]:
        """Stored, tagged findings decided under a different registry, policy or reputation list."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM findings WHERE json_extract(detail, '$.tag') IS NOT NULL AND ("
                "COALESCE(json_extract(detail, '$.domain_auth.registry_version'), '') != ? OR "
                "COALESCE(json_extract(detail, '$.policy_version'), '') != ? OR "
                "(? IS NOT NULL AND COALESCE(json_extract(detail, '$.reputation_version'), '') != ?)) ORDER BY id",
                (registry_version, policy_version, reputation_version, reputation_version),
            ).fetchall()
        return [int(r["id"]) for r in rows]

    def update_finding_policy(self, finding_id: int, fields: Mapping[str, Any]) -> dict | None:
        """Apply a re-evaluated verdict to a stored finding, keeping the previous one in history."""
        with self._lock, self.conn:
            row = self.conn.execute("SELECT detail FROM findings WHERE id = ?", (int(finding_id),)).fetchone()
            if row is None:
                return None
            detail = json.loads(row["detail"] or "{}")
            history = list(detail.get("verdict_history") or [])
            old_auth = detail.get("domain_auth") or {}
            if detail.get("tag") != fields.get("tag") or old_auth.get("status") != (fields.get("domain_auth") or {}).get("status"):
                history.append({
                    "at": utc_now(), "tag": detail.get("tag"), "domain_auth_status": old_auth.get("status"),
                    "registry_version": old_auth.get("registry_version"), "policy_version": detail.get("policy_version"),
                })
            for key in ("tag", "manual_review", "domain_auth", "trust_reasons", "blockable", "policy_version",
                        "maliciousness", "reputation_version", "reason_codes", "final_domain_auth"):
                if key in fields:
                    detail[key] = fields[key]
            detail["verdict_history"] = history[-20:]
            self.conn.execute("UPDATE findings SET detail = ? WHERE id = ?", (_json(detail), int(finding_id)))
        return self.get_finding(int(finding_id))

    def finding_source(self, finding_id: int) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(json_extract(f.detail, '$.source'), d.source) AS source "
                "FROM findings f JOIN domains d ON d.id = f.domain_id WHERE f.id = ?",
                (int(finding_id),),
            ).fetchone()
        return str(row["source"]) if row and row["source"] is not None else None

    def verdict_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT COALESCE(json_extract(detail, '$.tag'), verdict) AS label, COUNT(*) AS n "
                "FROM findings GROUP BY label"
            ).fetchall()
        return {str(r["label"]): int(r["n"]) for r in rows}

    # ------------------------------------------------------------------ users / sessions / audit

    def user_count(self) -> int:
        with self._lock:
            return int(self.conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])

    def create_user(self, username: str, password_hash: str, role: str) -> dict:
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO users(username, password_hash, role, active, created_at) VALUES(?, ?, ?, 1, ?)",
                (username, password_hash, role, utc_now()),
            )
        return {"id": int(cur.lastrowid), "username": username, "role": role, "active": True}

    def get_user(self, username: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, username, role, active, created_at, last_login_at FROM users ORDER BY id"
            ).fetchall()
        return [dict(r) | {"active": bool(r["active"])} for r in rows]

    def set_user_active(self, username: str, active: bool) -> bool:
        with self._lock, self.conn:
            cur = self.conn.execute("UPDATE users SET active = ? WHERE username = ?", (1 if active else 0, username))
            if not active:
                self.conn.execute(
                    "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,)
                )
        return cur.rowcount > 0

    def set_user_password(self, username: str, password_hash: str) -> bool:
        with self._lock, self.conn:
            cur = self.conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
            self.conn.execute(
                "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,)
            )
        return cur.rowcount > 0

    def touch_login(self, user_id: int) -> None:
        with self._lock, self.conn:
            self.conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now(), int(user_id)))

    def create_session(self, token_hash: str, user_id: int, csrf_token: str, expires_at: str) -> None:
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM sessions WHERE expires_at < ?", (utc_now(),))
            self.conn.execute(
                "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at) VALUES(?, ?, ?, ?, ?)",
                (token_hash, int(user_id), csrf_token, utc_now(), expires_at),
            )

    def session_user(self, token_hash: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT u.id, u.username, u.role, u.active, s.csrf_token, s.expires_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
        return dict(row) if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def audit(self, *, username: str | None, action: str, target: str | None = None, outcome: str = "ok",
              client_ip: str | None = None, detail: Mapping[str, Any] | None = None) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO audit_log(at, username, action, target, outcome, client_ip, detail) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (utc_now(), username, action, target, outcome, client_ip, _json(dict(detail or {}))),
            )

    def list_audit(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 1000)),)
            ).fetchall()
        return [dict(r) | {"detail": json.loads(r["detail"] or "{}")} for r in rows]

    # ------------------------------------------------------------------ status

    # ------------------------------------------------------------------ sweep (WS2)

    _SWEEP_COLUMNS = ("position", "url", "title", "snippet", "verdict", "score", "reasons", "finding_id")

    def create_sweep_run(self, *, query: str, lang: str, channel: str, engine: str, cached: bool,
                         query_id: str | None = None) -> dict:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO sweep_runs(query, lang, channel, engine, cached, created_at, query_id) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (query, lang, channel, engine, int(bool(cached)), now, query_id),
            )
        return {"id": int(cur.lastrowid), "query": query, "lang": lang, "channel": channel,
                "engine": engine, "cached": bool(cached), "created_at": now, "query_id": query_id}

    def update_sweep_run(self, run_id: int, **fields: Any) -> None:
        """Merge status/stage/engine/... into the run's JSON state (and engine/cached columns)."""
        with self._lock, self.conn:
            row = self.conn.execute("SELECT state FROM sweep_runs WHERE id = ?", (int(run_id),)).fetchone()
            if row is None:
                return
            state = json.loads(row["state"] or "{}")
            state.update(fields)
            if fields.get("status") in ("completed", "failed"):
                state["finished_at"] = utc_now()
            self.conn.execute("UPDATE sweep_runs SET state = ? WHERE id = ?", (_json(state), int(run_id)))
            if "engine" in fields:
                self.conn.execute("UPDATE sweep_runs SET engine = ? WHERE id = ?", (str(fields["engine"]), int(run_id)))
            if "cached" in fields:
                self.conn.execute("UPDATE sweep_runs SET cached = ? WHERE id = ?", (int(bool(fields["cached"])), int(run_id)))

    def list_sweep_runs(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT r.*, COUNT(s.id) AS result_count FROM sweep_runs r "
                "LEFT JOIN sweep_results s ON s.run_id = r.id GROUP BY r.id "
                "ORDER BY r.id DESC LIMIT ?",
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        return [
            {"id": r["id"], "query": r["query"], "query_id": r["query_id"], "lang": r["lang"],
             "channel": r["channel"], "engine": r["engine"], "cached": bool(r["cached"]),
             "created_at": r["created_at"], "result_count": int(r["result_count"]),
             **{k: v for k, v in json.loads(r["state"] or "{}").items() if k in ("status", "stage", "source_kind", "finished_at", "error")}}
            for r in rows
        ]

    def add_sweep_results(self, run_id: int, results: Iterable[Mapping[str, Any]]) -> None:
        rows = []
        for item in results:
            detail = {k: v for k, v in item.items() if k not in self._SWEEP_COLUMNS}
            rows.append((run_id, int(item["position"]), str(item["url"]), item.get("title"), item.get("snippet"),
                         item.get("verdict"), item.get("score"), _json(item.get("reasons") or []),
                         item.get("finding_id"), _json(detail)))
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO sweep_results(run_id, position, url, title, snippet, verdict, score, reasons, "
                "finding_id, detail) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def get_sweep_run(self, run_id: int) -> dict | None:
        with self._lock:
            run = self.conn.execute("SELECT * FROM sweep_runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                return None
            rows = self.conn.execute(
                "SELECT * FROM sweep_results WHERE run_id = ? ORDER BY position", (run_id,)
            ).fetchall()
        results = []
        for row in rows:
            item = {key: row[key] for key in self._SWEEP_COLUMNS}
            item["reasons"] = json.loads(row["reasons"] or "[]")
            item.update(json.loads(row["detail"] or "{}"))
            results.append(item)
        state = json.loads(run["state"] or "{}")
        return {"id": run["id"], "query": run["query"], "lang": run["lang"], "channel": run["channel"],
                "engine": run["engine"], "cached": bool(run["cached"]), "created_at": run["created_at"],
                "query_id": run["query_id"], **state, "results": results}

    def counts(self, mode: str = "live") -> dict[str, int]:
        evidence_files = len(list(self.evidence_dir.glob("*.jpg")))
        with self._lock:
            domain_count = self.conn.execute("SELECT COUNT(*) AS n FROM domains").fetchone()["n"]
            finding_count = self.conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
        return {
            "domains": int(domain_count),
            "findings": int(finding_count),
            "evidence": evidence_files,
        }
