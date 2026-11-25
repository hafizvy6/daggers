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
    detail          TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS guard_hits (
    domain          TEXT PRIMARY KEY,
    count           INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL
);

-- Guard (live block list). The list itself, daily block counters (no client data), events and
-- what was pushed to external providers. Additive tables only; nothing existing is changed.
CREATE TABLE IF NOT EXISTS guard_blocklist (
    domain          TEXT PRIMARY KEY,          -- punycode host, lower-case
    active          INTEGER NOT NULL DEFAULT 1,
    source          TEXT NOT NULL,             -- checker | radar | sweep | investigation | seed
    finding_id      INTEGER,
    tag             TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    score           REAL NOT NULL DEFAULT 0,
    reason          TEXT NOT NULL DEFAULT '',
    listed_at       TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    delisted_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_guard_blocklist_active ON guard_blocklist(active, listed_at);
CREATE TABLE IF NOT EXISTS guard_daily (
    day             TEXT PRIMARY KEY,          -- YYYY-MM-DD (UTC)
    hits            INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS guard_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,             -- listed | delisted | hit | sync
    domain          TEXT,
    source          TEXT,
    detail          TEXT NOT NULL DEFAULT '{}',
    at              TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guard_pushed (
    provider        TEXT NOT NULL,
    domain          TEXT NOT NULL,
    pushed_at       TEXT NOT NULL,
    PRIMARY KEY (provider, domain)
);

CREATE TABLE IF NOT EXISTS feed_labels (
    domain          TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    confirmed       INTEGER NOT NULL DEFAULT 1,
    updated_at      TEXT NOT NULL
);

-- Exact URLs from phishing / malware feeds. A URL listing confirms THAT URL; it is not, by
-- itself, a verdict on every other page of a (possibly shared) host.
CREATE TABLE IF NOT EXISTS feed_urls (
    url_key         TEXT PRIMARY KEY,
    host            TEXT NOT NULL,
    source          TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feed_urls_host ON feed_urls(host);

CREATE TABLE IF NOT EXISTS meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_domains_enqueued ON domains(enqueued, first_seen);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_sweep_results_run ON sweep_results(run_id, position);

-- ---------------------------------------------------------------- integration (v2)
-- findings.detail / reports.ai are added by Repository.initialize() migrations for
-- pre-existing databases; fresh databases get them from the ALTERs too.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'investigator', 'viewer')),
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash      TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    username        TEXT,
    action          TEXT NOT NULL,
    target          TEXT,
    outcome         TEXT NOT NULL DEFAULT 'ok',
    client_ip       TEXT,
    detail          TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sweep_runs_created ON sweep_runs(created_at DESC);

-- ---------------------------------------------------------------- live Checker (v3)
-- One row per Checker submission. request_id is generated by the client for each
-- click on "Check it": retries / refreshes / double clicks return the same finding.
CREATE TABLE IF NOT EXISTS check_requests (
    request_id      TEXT PRIMARY KEY,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    content_hash    TEXT NOT NULL,
    client_hash     TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_check_requests_content ON check_requests(content_hash, client_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC, id DESC);
