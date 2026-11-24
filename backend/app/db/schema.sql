PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL UNIQUE,
    source          TEXT,
    cert_names      TEXT,
    first_seen      TEXT NOT NULL,
    rdap_created    TEXT,
    rdap_registrar  TEXT,
    dns_a           TEXT,
    tls_issued      TEXT,
    tls_issuer      TEXT,
    favicon_hash    TEXT,
    enqueued        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    score           REAL NOT NULL,
    verdict         TEXT NOT NULL,
    reasons         TEXT NOT NULL,
    l1_detail       TEXT NOT NULL DEFAULT '{}',
    rendered        INTEGER NOT NULL DEFAULT 0,
    evidence_path   TEXT,
    gallery_match   TEXT,
    clone_score     REAL,
    created_at      TEXT NOT NULL,
    is_case_file    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    auto            INTEGER NOT NULL DEFAULT 1,
    evidence        TEXT NOT NULL,
    filed_at        TEXT,
    blocked_hits    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sweep_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    query           TEXT NOT NULL,
    lang            TEXT NOT NULL DEFAULT 'en',
    channel         TEXT NOT NULL,
    engine          TEXT NOT NULL,
    cached          INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sweep_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES sweep_runs(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    url             TEXT NOT NULL,
    title           TEXT,
    snippet         TEXT,
    verdict         TEXT,
    score           REAL,
    reasons         TEXT,
    finding_id      INTEGER,
    detail          TEXT
);

CREATE TABLE IF NOT EXISTS guard_hits (
    domain          TEXT PRIMARY KEY,
    count           INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_labels (
    domain          TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    confirmed       INTEGER NOT NULL DEFAULT 1,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_domains_enqueued ON domains(enqueued, first_seen);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_sweep_results_run ON sweep_results(run_id, position);
