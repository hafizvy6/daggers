# Daggers — Integration report and deployment readiness

Inputs: `ws1.zip` (daggers-hafiz, Intelligence Engine), `ws2.zip` (daggers-mohammed, Shield &
Channels + WS1 patches), `ws3.zip` (daggers-azhar, Face & Analyst). Output: one repository, one
backend, one database, one verdict path, Police Portal as the primary interface.

## 1. Base and merge order

1. WS1 repository as the base (its backend, DB layer and contracts were the most complete).
2. WS2 files added; WS2's five proposed WS1 patches (0001–0005: tag field, guard filtering, scorer
   hook, UI tag mapping, runbook) **applied** and the `patches/` folder removed.
3. WS3 `web/`, `backend/app/ai/`, AI/report routes, ops gates and design docs added; WS3
   stand-in server and store not copied.
4. Integration layer written (auth, investigations, system routes, production config) and the
   three sets of tests moved under `backend/tests/` (`ws2/`, `ws3/`).

## 2. Changes per workstream

**WS1 (Intelligence Engine)** — scorer, radar, vision, claims unchanged in logic.
* `main.py`: explicit router list; Runtime gained the trust policy, auth limiters, readiness,
  `tag()` on every read, `investigate()`, sweep finding sink, security-headers middleware.
* `verdicts`: UNKNOWN mapped to WARNING (was SAFE).
* `db/schema.sql` + `repo.py`: users/sessions/audit tables; additive migrations (finding detail,
  report AI, sweep state); restricted findings; all new SQL kept in `repo.py`.
* `config.py`: `APP_ENV` (dev/production) and security settings.
* `api/scan.py`: per-IP rate limit, threadpool. `api/health.py`: mode change admin-only; healthz 503.
* `api/findings.py`: tags on every finding; restricted findings need a session.

**WS2 (Shield & Channels)**
* `channels/scoring.py`: `tag_finding()` for stored/radar findings; host and signals exposed.
* `channels/sweep.py`, `sweep_store.py`: background runs with persisted status/stage/error, run list,
  finding sink; “no engine” is an error, not empty success.
* `search.py`/`maps.py`: fixtures can be disabled; production disables them.
* `api/sweep.py`: roles, 202 + polling, `?wait=true`. `api/guard.py`: shared runtime registry.
* Extension unchanged in logic (it already used the backend `tag`); README updated.

**WS3 (Face & Analyst)**
* `web/js/api.js`: session handling, CSRF, timeouts, `tagFor()` (backend tag first), new `/api/scan`
  body, sweep polling, private-data cache rules; offline heuristic can no longer return SAFE.
* New login view, portal workspace (investigate, investigations, sweeps, Guard sync, audit for
  admins), finding page shows trust reasons, authentication and verification evidence.
* CSP compliance (`js/main.js` external), service worker caches public API only, i18n keys added (EN/AR parity).
* `backend/app/ai`: evidence input now includes tag, trust reasons, authentication and official
  sources; fallback template and prompts rewritten to state only evidence (FACTS/ASSESSMENT/MISSING/NEXT STEPS).
* `api/reports.py`, `api/ai.py`: rewritten on the WS1 repository with roles and audit.

## 3. Duplicates removed

| Removed | Kept instead |
|---|---|
| WS3 `backend/app/server.py` (stand-in server) | WS1 `main.py` |
| WS3 `backend/app/store.py` (in-memory store) | WS1 `repo.py` (SQLite) |
| WS3 verdict→tag table in the UI | backend `tag` via `tagFor()` |
| WS3 `test_server.py` (tested the removed server) | `test_integration.py` |
| WS1 optional-router probing | explicit `ROUTERS` |
| WS2 `patches/` | patches applied |
| WS2 in-memory sweep store as default | SQLite store (memory store kept for tests) |

## 4. Contract changes (all additive unless noted)

* Scan/finding: `tag`, `trust_reasons`, `domain_auth`, `gov_verification`, `manual_review`,
  `policy_version` added; `verdict` kept.
* `POST /api/scan` body is `{kind, input, lang}` (WS3 client updated).
* **Breaking**: sweeps return 202 and run in the background (`?wait=true` for synchronous);
  reports, AI, sweeps, investigations and mode switching require a portal session + CSRF.
* New: `/api/auth/*`, `/api/admin/*`, `/api/investigations`, `/api/readiness`, `/api/registry`, `/api/sweep` (list).

## 5. Portal data path (verified by tests)

Portal → `POST /api/investigations` → Runtime.investigate → WS1 scorer → WS2 registry + verification
→ trust policy → `repo.insert_finding` (detail JSON) → audit → response → `#/finding/{id}` reads
`GET /api/finding/{id}` → report → AI analysis on stored evidence → export pack.

## 6. Deployment readiness matrix

| Capability | Implemented | Tested | Prod-configured | Needs credentials | Needs authorisation |
|---|---|---|---|---|---|
| Central verdict / trust policy | ✅ | ✅ | ✅ | — | — |
| SAFE for official sites | ✅ | ✅ (synthetic registry) | ⚠️ registry all pending | — | ✅ human registry approval |
| Official claim verification (live sources) | ✅ | ✅ recorded/synthetic sources | ✅ | — (public sites) | ✅ source terms review |
| Portal auth, roles, CSRF, audit | ✅ | ✅ | ✅ | — | — |
| Investigations → stored findings | ✅ | ✅ unit + browser | ✅ | — | — |
| Reports, export pack | ✅ | ✅ | ✅ | — | — |
| AI Analyst | ✅ | ✅ template provider | ✅ | Gemini/Groq keys (optional) | data-sharing approval for external LLMs |
| Web sweep | ✅ | ✅ fake providers | ✅ fixtures off | Serper key (DDG fallback untested live) | provider terms |
| Maps sweep | ✅ | ✅ fake providers | ✅ | Google Places key | provider terms |
| Radar (crt.sh/feeds/render) | ✅ (WS1) | ✅ unit | off by default | feed keys where applicable | — |
| Guard blocklist | ✅ | ✅ | ✅ | NextDNS key (operator push) | network owner approval |
| Chrome extension | ✅ | ✅ unit + real Chrome | backend URL configurable | — | Web Store account + review |
| Docker/Caddy HTTPS | ✅ config | ❌ not built | ✅ | domain + DNS | hosting approval |
| Backups/rollback | ✅ documented | ❌ | manual | — | — |

**Not implemented:** MFA/SSO, password reset by email, multi-instance scaling (Postgres/Redis),
data-retention jobs, Chrome Web Store package, automated CI pipeline, monitoring/alerting.

## 7. Update: live Checker (see docs/CHECKER.md)

The application is now live-only (the team's `daggers-main` decisions were adopted: no demo mode,
seed, fixtures or sample data anywhere in the runtime), phone-number checking was removed from the
Checker, the engine reports every signal with the part of the input that triggered it and analyses
message content, and every Checker result is stored as a finding visible in the Police Portal's
searchable **All findings** index.

## 8. Verdict on readiness

The integrated application is **feature-complete for a supervised pilot** and its behaviour is tested,
but it is **not yet production-ready** for police operations: it has not been run on real FastAPI
or in Docker, no registry entry is approved, live providers are untested, there is no MFA/SSO, and no
security review has been done. These are listed with steps in `DEPLOYMENT.md` §9 and `SECURITY.md`.
It is an unofficial prototype and is not endorsed or operated by Abu Dhabi Police.
