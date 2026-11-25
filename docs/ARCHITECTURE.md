# Daggers — Final architecture

## 1. Shape

One FastAPI process (modular monolith) serves the API **and** the PWA/Police Portal on the same
origin. SQLite (WAL) is the single database. Caddy terminates HTTPS in production. The Chrome
extension and Guard (NextDNS) are clients of the same API.

```
 Browser (PWA + Police Portal)      Chrome extension (MV3)        NextDNS (Guard)
        │ same-origin, cookie session      │ POST /api/scan            │ blocklist.txt
        ▼                                  ▼                           ▼
 ┌──────────────────────────── Caddy (HTTPS) ───────────────────────────────────────┐
 │ FastAPI app (backend/app/main.py)                                                │
 │  middleware: security headers · CORS (public, no credentials)                    │
 │  routers: auth · system · examples · check · findings · scan · health · stream · │
 │           investigations                                                         │
 │           reports · ai · sweep · guard                                           │
 │  Runtime ── the ONE verdict path ───────────────────────────────────────────┐   │
 │   core/scorer (WS1)  →  channels/scoring.ShieldScorer  →  trust_policy.decide │   │
 │   evidence, score        registry auth + claim verification   → tag           │   │
 │  radar/ (crt.sh, feeds, enrich) · vision/ · reports/queue (auto-file)        │   │
 │  channels/: search · maps · sweep (background jobs) · guard blocklist        │   │
 │  ai/: Gemini → Groq → evidence-only template (never sets the tag)            │   │
 │  security.py: scrypt passwords, sessions, roles, CSRF, rate limits, audit    │   │
 │  db/repo.py: ALL SQL ── SQLite WAL (findings, reports, sweeps, users, audit) │   │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Integration map (authoritative implementations)

| Shared concern | Authoritative implementation | Replaced / removed |
|---|---|---|
| Backend entry point | `backend/app/main.py` (WS1, extended) | WS3 `backend/app/server.py` (stand-in server) — removed |
| Data store | `backend/app/db/repo.py` + `schema.sql` (WS1, extended) | WS3 `backend/app/store.py` (in-memory) — removed |
| Scoring | `backend/app/core/scorer.py` (WS1) | WS3 `web/js/api.js` offline heuristic kept **only** for the offline tier; it can no longer emit SAFE |
| Final verdict / tag | `backend/app/channels/trust_policy.py` via `Runtime.tag()` / `scan()` / `investigate()` | WS1 `verdicts.UI_TAGS` (UNKNOWN→SAFE) corrected to UNKNOWN→WARNING; WS3 `VERDICT_TAG` (verdict→tag) replaced by `tagFor(object)` using the backend `tag` |
| Reports API | `backend/app/api/reports.py` on WS1 repo | WS3 store-backed version |
| AI Analyst | `backend/app/ai` (WS3) with server-built grounded evidence | WS3 template that asserted unverified facts — rewritten |
| Sweep storage | `RepoSweepStore` (SQLite) | WS2 in-memory store remains only as test/fallback implementation |
| Guard feed | WS1 `get_guard_rows` → `Runtime.guard_rows` (registry-filtered) → WS2 blocklist | — |
| Router mounting | explicit `ROUTERS` tuple in `main.py` | WS1 "optional router" probing |

## 3. Data flows

**Portal investigation (the mandatory end-to-end flow)**
`POST /api/investigations {url, page_text}` (investigator) → URL normalised (tracking params removed,
non-http rejected) → `ShieldScorer.assess_url` → WS1 `score_url` (lexical, identity, homograph,
claims) → registry authentication of the exact host → claim extraction + official verification
against approved records → `trust_policy.decide` → **finding persisted** (`findings` + `detail` JSON:
tag, domain_auth, gov_verification with evidence & provenance, signals, submitted URL,
investigator, policy version) → audit entry → response → portal navigates to `#/finding/{id}`,
which re-reads the stored record.

**Live Checker (the main public path)**: `POST /api/check` → `checker.classify` (URL/domain vs
message, normalisation, validation) → `core.scorer.score_request` (URL signals for the link, or for
every link in a message, + `core.message` content analysis: credential/OTP requests, payment
demands, delivery lures, urgency, brand/government impersonation, link shorteners) →
`ShieldScorer.apply_to_scan_result` (registry authentication of the link that drove the verdict +
official claim verification against records in the snapshot store) → `checker.redact` (personal
data removed from the message and excerpts) → `repo.insert_check_finding` (finding + request id in
one transaction; duplicates by request id / same input within 120 s) → response = the stored
finding → Police Portal `GET /api/portal/findings`, `GET /api/finding/{id}`.

**Extension**: `POST /api/scan` → the same engine + trust policy → `tag`; input is not stored.

**Sweep**: `POST /api/sweep` → run row (status running) → background thread → provider chain →
each result scored by the same path → results stored → FAKE/MISLEADING live results become findings
(`source = sweep:web|maps`) → run status completed/failed → SSE `sweep`.

**Radar**: WS1 pipeline writes findings; every read (`/api/feed`, `/api/finding`, SSE) passes through
`Runtime.tag()` so radar findings carry the same tag.

**Report → AI**: `POST /api/reports` stores zero-PII evidence (C1 + tag + evidence_id).
`POST /api/report/{id}/analysis` builds the AI input server-side from the stored report + finding
(authentication, verification sources) and stores the result on the report.

**Guard**: `Runtime.guard_rows` (MALICIOUS, never registry domains) → `/api/guard/feed` and the WS2
blocklist (MALICIOUS only, valid names, ≤30 days, deduplicated) → NextDNS script (manual).

## 4. Database (SQLite, WAL)

| Table | Purpose | Notes |
|---|---|---|
| `domains`, `findings` | findings and their domain | `findings.detail` JSON (migration) holds tag, authentication, verification evidence, signals, source and, for Checker findings, the full analysis |
| `reports` | police reports | `evidence` zero-PII JSON; `ai` JSON (migration) |
| `sweep_runs`, `sweep_results` | sweeps | `sweep_runs.state` (status/stage/source_kind/errors), `query_id`; `sweep_results.detail` |
| `users`, `sessions`, `audit_log` | portal security | sessions store SHA-256 of the token only |
| `check_requests` | Checker de-duplication | `request_id` (PK) → finding, content hash, client hash, time |
| `guard_hits`, `feed_labels`, `meta` | engine | `meta.schema_version = 3` |

Migrations are additive and idempotent (`Repository._migrate`), so existing databases upgrade in
place. Findings are never overwritten by investigations: each investigation inserts a new row.

## 5. Environments

There is one runtime mode: **live**. `APP_ENV` only changes hardening.

| | dev | production |
|---|---|---|
| Data | live database only — no seed, no fixtures | same |
| Search/Maps | live providers when configured; otherwise sweeps fail honestly | same |
| Cookies | not Secure (plain HTTP on localhost) | Secure + HSTS |
| API docs | on | off |
