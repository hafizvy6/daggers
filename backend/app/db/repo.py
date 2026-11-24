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


def _json_with_default(value: Any) -> str:
    """JSON for additive sweep fields; unusual objects degrade to strings."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


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


class Repository:
    """All SQL and all SQLite orchestration lives here. No seed data is inserted."""

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
                # Additive migration for databases created before the sweep columns landed.
                columns = {
                    str(row["name"])
                    for row in self._conn.execute("PRAGMA table_info(sweep_results)").fetchall()
                }
                if "detail" not in columns:
                    self._conn.execute("ALTER TABLE sweep_results ADD COLUMN detail TEXT")
                self._conn.commit()
        return missing

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
        return canonical_finding(
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
            }
        )

    def get_finding(self, finding_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, d.source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file "
                "FROM findings f JOIN domains d ON d.id = f.domain_id WHERE f.id = ?",
                (int(finding_id),),
            ).fetchone()
        return self._row_to_finding(row) if row else None

    def get_findings(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with self._lock:
            rows = self.conn.execute(
                "SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                "COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, d.source, "
                "COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                "f.gallery_match, f.is_case_file "
                "FROM findings f JOIN domains d ON d.id = f.domain_id "
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
        )
        with self._lock, self.conn:
            if finding_id is None:
                cursor = self.conn.execute(
                    "INSERT INTO findings("
                    "domain_id, score, verdict, reasons, l1_detail, rendered, evidence_path, "
                    "gallery_match, clone_score, created_at, is_case_file"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
                new_id = int(cursor.lastrowid)
            else:
                self.conn.execute(
                    "INSERT OR IGNORE INTO findings("
                    "id, domain_id, score, verdict, reasons, l1_detail, rendered, evidence_path, "
                    "gallery_match, clone_score, created_at, is_case_file"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (int(finding_id), *values),
                )
                new_id = int(finding_id)
        return self.get_finding(new_id) or canonical_finding({"id": new_id, "domain": domain})

    def set_finding_evidence(self, finding_id: int, evidence_url: str) -> dict | None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE findings SET evidence_path = ?, rendered = 1 WHERE id = ?",
                (evidence_url, int(finding_id)),
            )
        return self.get_finding(finding_id)

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
        return self.get_finding(finding_id)

    def evidence_path(self, finding_id: int) -> Path | None:
        finding = self.get_finding(int(finding_id))
        if not finding or not finding["evidence_url"]:
            return None
        url = str(finding["evidence_url"])
        return self.evidence_dir / Path(url).name

    def ensure_evidence_file(self, finding_id: int) -> Path | None:
        """Return an existing real evidence file, or None. Never invent one."""
        destination = self.evidence_path(int(finding_id))
        if destination is None:
            return None
        return destination if destination.exists() and destination.stat().st_size > 0 else None

    def find_evidence_url(self, domain: str) -> str | None:
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

    def get_guard_rows(self, guard_block_misleading: bool = False) -> list[dict]:
        verdicts = ["MALICIOUS", "MISLEADING"] if guard_block_misleading else ["MALICIOUS"]
        placeholders = ",".join("?" for _ in verdicts)
        with self._lock:
            rows = self.conn.execute(
                f"SELECT f.id, d.domain, f.verdict, f.score, f.reasons, "
                f"COALESCE(d.tls_issued, f.created_at) AS cert_issued, d.first_seen, d.source, "
                f"COALESCE(f.clone_score, 0) AS clone, f.evidence_path AS evidence_url, "
                f"f.gallery_match, f.is_case_file, f.created_at "
                f"FROM findings f JOIN domains d ON d.id = f.domain_id "
                f"WHERE f.verdict IN ({placeholders}) AND f.id = ("
                f"SELECT MAX(f2.id) FROM findings f2 WHERE f2.domain_id = f.domain_id "
                f"AND f2.verdict IN ({placeholders})) "
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

    def guard_stats(self, guard_block_misleading: bool = False) -> dict:
        rows = self.get_guard_rows(guard_block_misleading)
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
        return canonical_report(dict(row))

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

    def set_report_status(self, report_id: int, status: str, filed_at: str | None = None) -> dict | None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE reports SET status = ?, filed_at = COALESCE(?, filed_at) WHERE id = ?",
                (status, filed_at, int(report_id)),
            )
        return self.get_report(int(report_id))

    # ---------------------------------------------------------------- sweeps

    def create_sweep_run(
        self,
        *,
        query: str,
        lang: str,
        channel: str,
        engine: str,
        cached: bool,
    ) -> dict:
        created_at = utc_now()
        with self._lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO sweep_runs(query, lang, channel, engine, cached, created_at) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (str(query), str(lang), str(channel), str(engine), 1 if cached else 0, created_at),
            )
            run_id = int(cursor.lastrowid)
        return {
            "id": run_id,
            "query": str(query),
            "lang": str(lang),
            "channel": str(channel),
            "engine": str(engine),
            "cached": bool(cached),
            "created_at": created_at,
            "query_id": None,
        }

    def add_sweep_results(self, run_id: int, results: Iterable[Mapping[str, Any]]) -> None:
        base_keys = {
            "position", "url", "title", "snippet", "verdict", "score",
            "reasons", "finding_id",
        }
        rows: list[tuple[Any, ...]] = []
        for index, result in enumerate(results, 1):
            item = dict(result)
            reasons = item.get("reasons") or []
            if isinstance(reasons, str):
                reasons = [reasons]
            detail = {key: value for key, value in item.items() if key not in base_keys}
            rows.append(
                (
                    int(run_id),
                    int(item.get("position") or index),
                    str(item.get("url") or ""),
                    item.get("title"),
                    item.get("snippet"),
                    item.get("verdict"),
                    float(item.get("score") or 0.0),
                    _json_with_default(list(reasons)),
                    item.get("finding_id"),
                    _json_with_default(detail),
                )
            )
        if not rows:
            return
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO sweep_results(run_id, position, url, title, snippet, verdict, "
                "score, reasons, finding_id, detail) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def get_sweep_run(self, run_id: int) -> dict | None:
        def loads(raw: Any, default: Any) -> Any:
            if raw is None or raw == "":
                return default
            try:
                return json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                return default

        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM sweep_runs WHERE id = ?", (int(run_id),)
            ).fetchone()
            if row is None:
                return None
            stored = self.conn.execute(
                "SELECT * FROM sweep_results WHERE run_id = ? ORDER BY position, id",
                (int(run_id),),
            ).fetchall()

        results: list[dict] = []
        for stored_row in stored:
            detail = loads(stored_row["detail"], {})
            if not isinstance(detail, dict):
                detail = {}
            reasons = loads(stored_row["reasons"], [])
            if not isinstance(reasons, list):
                reasons = [str(reasons)]
            result = {
                "position": int(stored_row["position"]),
                "url": str(stored_row["url"] or ""),
                "title": stored_row["title"],
                "snippet": stored_row["snippet"],
                "verdict": stored_row["verdict"],
                "score": float(stored_row["score"] or 0.0),
                "reasons": reasons,
                "finding_id": stored_row["finding_id"],
            }
            result.update(detail)
            results.append(result)
        return {
            "id": int(row["id"]),
            "query": str(row["query"]),
            "lang": str(row["lang"]),
            "channel": str(row["channel"]),
            "engine": str(row["engine"]),
            "cached": bool(row["cached"]),
            "created_at": str(row["created_at"]),
            "query_id": None,
            "results": results,
        }

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

    def confirmed_domains(self) -> set[str]:
        with self._lock:
            rows = self.conn.execute("SELECT domain FROM feed_labels WHERE confirmed = 1").fetchall()
        return {str(row["domain"]) for row in rows}

    # ------------------------------------------------------------------ status

    def counts(self) -> dict[str, int]:
        evidence_files = len(list(self.evidence_dir.glob("*.jpg")))
        with self._lock:
            domain_count = self.conn.execute("SELECT COUNT(*) AS n FROM domains").fetchone()["n"]
            finding_count = self.conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
        return {
            "domains": int(domain_count),
            "findings": int(finding_count),
            "evidence": evidence_files,
        }
