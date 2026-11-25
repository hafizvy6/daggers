# Daggers — API contract (integrated)

Base URL: same origin as the portal (e.g. `https://daggers.example.org`). JSON unless stated.
Auth = Police Portal session cookie `daggers_session` (HttpOnly, SameSite=Strict, Secure in production).
**Every non-GET request that requires a role must send `X-CSRF-Token`** (value returned by
`/api/auth/login` and `/api/auth/me`). Roles are ordered `viewer < investigator < admin`.

Errors use FastAPI's shape `{"detail": "..."}` (422 validation errors carry a list).
Common codes: 401 not signed in · 403 role/CSRF · 404 · 409 conflict · 422 invalid input ·
429 rate limited · 503 dependency unavailable.

## Verdict fields (all finding/scan payloads)

| Field | Meaning |
|---|---|
| `verdict` | WS1 brain verdict `MALICIOUS / MISLEADING / SUSPICIOUS / UNKNOWN` (kept for compatibility) |
| `tag` | **final** label `SAFE / WARNING / MISLEADING / FAKE` — clients must display this |
| `trust_reasons` | short reasons for the tag |
| `domain_auth` | registry result for the exact host: `{status, authenticated, legitimate_site, host, entry_id, organization, source_class, reason, registry_version, reviewer, verified_at, expires_at}`; status ∈ `AUTHENTICATED, INDEPENDENT_MEDIA, VERIFIED_ORGANIZATION, REPUTABLE_SITE, ESTABLISHED_SITE, UNLISTED, PENDING, REVOKED, EXPIRED, NOT_CHECKABLE`. `authenticated` = approved government source (class A/B); `legitimate_site` = approved news outlet (C), verified organisation (P) widely used site not in the registry (`REPUTABLE_SITE`, source_class `R`) or established website (`ESTABLISHED_SITE`, source_class `E`, with `established: {status, basis, age_days, years, since}`) — SAFE allowed, **never** an official source. `reputation` (when the reputation check ran): `{status: REPUTABLE|NOT_RANKED|SHARED_HOST|LIST_MISSING|LIST_STALE|LIST_INVALID, trusted, host, domain, rank, source: "Tranco", list_id, list_date, reason}`. Clients show SAFE only when `tag` is SAFE **and** one of the two is true. |
| `gov_verification` | `null` when no government claim was found; otherwise status ∈ `VERIFIED, CONTRADICTED, NOT_VERIFIABLE, SOURCE_UNAVAILABLE, SOURCE_EXPIRED, CONFLICTING_SOURCES` with the extracted claim and evidence items (role, comparison, source class, entry id, organization, source URL, published/retrieved dates, excerpt) |
| `manual_review` | true when an officer should review before acting |
| `policy_version` | trust policy version (`daggers-trust-2.2` (reason codes, evidence and redirect rule are additive)) — see [GOVERNMENT-SAFE.md](GOVERNMENT-SAFE.md) |
| `reason_codes` | stable code per `trust_reasons` entry (same order), e.g. `AUTH_GOV_APPROVED`, `REPUTATION_WIDELY_USED`, `REDIRECT_OFF_TRUSTED_SITE`, `CLAIM_CONTRADICTED`; table in `channels/trust_policy.py` (`REASON_CODES`). Unknown texts map to `OTHER` |
| `evidence` | `[{id: registry|reputation|domain_age|page|feeds|claim_verification, source, status, checked_at, data_updated_at?, summary, …}]` — what was checked, the result and its freshness; a source that could not be checked says so |
| `live_evidence` | Checker / investigations only: `{domain_age: {domain, status, registered_at, age_days, source, checked_at, registrar}, page: {status, original_host, final_host, redirected, hops[], page: {title, forms[], …}}, feeds}`; `null` for `/api/scan` and Sweep (no live outbound calls) |
| `final_domain_auth` | registry/reputation authentication of the host the link redirects to (or `null`) |
| `signals[].group` | evidence group; signals of one observation count once (others shown with weight 0) |
| `gov_verification.evidence[].attributes` | `{authority, jurisdiction, service, amount, effective_date}` → `match|differs|not_stated|not_compared` |
| `reputation_version` | reputation list the verdict was decided under (`rep_none` / `rep_off` when none) — a new list re-tags stored findings |
| `maliciousness` | stored maliciousness evidence used to re-evaluate the finding when the registry changes |
| `verdict_history` | (finding detail) earlier tags `{at, tag, domain_auth_status, registry_version, policy_version}`, last 20 — written when a stored finding is re-tagged after a registry/policy change |

## Public endpoints (no account)

| Method & path | Notes |
|---|---|
| `POST /api/check` | **The live Checker.** Body `{input: ≤4000 chars, lang: "en"|"ar", request_id: 8–64 [A-Za-z0-9_-]}`. The server classifies the input (URL/domain or message), normalises it, runs the engine + central verdict policy, removes personal data from messages, and **stores the result as a finding** (source `checker`, visible only in the Police Portal). The Checker is **independent of the Police Portal**: it SENDS each new result to the Portal and keeps its own result store (`CHECKER_STORE_PATH`); it never reads Portal findings, cases or evidence. Response = the result that was sent (see "Checker finding" below) + `duplicate`. **201** new analysis (sent to the Portal) · **200** same `request_id`, or the same input while its stored result is valid (`CHECK_CACHE_TTL_S`, default 6 h; 10 min when a source could not be checked; any registry / policy / reputation / engine change invalidates it) → the stored result, `duplicate: true`, `cached: true`, `cached_at` — nothing re-analysed or re-sent. **422** `{detail:{code,message}}` — `empty`, `too_short`, `too_long`, `unsupported_scheme`, `invalid_url`, `invalid_host`, `url_too_long`, `bad_request_id`. **429** `rate_limited` (`SCAN_RATE_PER_MIN` per client). **503** `analysis_failed` (nothing stored, `result: null`) or `persist_failed` (`result` = the unsaved analysis with `id: null`). Timeout in the browser: 30 s. Response also carries `guard` — the live Guard state for the domain (a FAKE link check is listed at once; message text never). |
| `POST /api/scan` | `?guard=1` adds a read-only `guard` lookup (never lists anything). For the Chrome extension. Body `{kind: "url"|"text", input: ≤4000 chars, lang: "en"|"ar"}`. Same engine and verdict policy as `/api/check`, but the input is **not stored**. Rate limit `SCAN_RATE_PER_MIN` per client IP → 429. Fails closed: scorer/policy errors return WARNING, never SAFE. Phone numbers are not an accepted input (422). |
| `GET /api/feed?limit=` | radar findings (tagged). Investigation findings appear only for signed-in users. |
| `GET /api/finding/{id}` | one finding; investigation findings require `viewer`. |
| `GET /api/evidence/{id}` / `{id}.jpg` | evidence metadata / screenshot |
| `GET /api/stream` | SSE: `finding`, `sweep`, `heartbeat`, `guard` (`listed` / `delisted` / `hit` / `sync`); investigation findings are never broadcast |
| `GET /api/guard/feed` | JSONL `{domain, verdict, reason, flagged_at}` — the live Guard list (FAKE only) |
| `GET /api/guard/stats` | original keys (`blocked_domains`, `feed_size`, `blocked_hits`, `blocked_today`, `mode`) plus `status`, `enabled`, `guard_mode`, `dot_hostname` (null = not configured), `doh_url`, `blocklist_url`, `domains_url`, `adguard_url`, `blocklist_count`, `blocked_total`, `newest_fakes[]` (`domain, source, score, reason, listed_at, finding_id` — null for Checker/investigation), `last_sync_at`, `sync_health` (`ok`/`error`/`rate_limited`/`never`), `nextdns_configured`, `nextdns_blocked_24h`, `honest_limits_key` |
| `GET /api/guard/blocklist.txt?format=hosts\|domains` | hosts (`0.0.0.0 d`) or bare domains; weak `ETag` (+`If-None-Match` → 304), `Cache-Control: max-age=60` |
| `GET /api/guard/domains.txt` | one domain per line |
| `GET /api/guard/adguard-rules.txt` | `\|\|d^`, or `\|\|d^$dnsrewrite=NOERROR;A;<GUARD_VERDICT_IP>` |
| `GET /api/guard/sync-status` | Guard sync status (`source: guard_feed`, provider push results, errors) |
| `POST /api/guard/sync` | sync now → status + `ok`; **429** + `Retry-After` within `GUARD_SYNC_COOLDOWN_S` |
| `GET /api/guard/check?domain=&live=0\|1` | O(1) lookup `{guard:{domain, valid, blocked, matched, source, listed_at, reason}}`; `live=1` also runs the engine on `https://domain/` (`scan`, `listed_now`; rate-limited like `/api/scan`) |
| `GET /api/guard/verdict?domain=&hit=0\|1` | verdict-page data; `hit=1` counts one anonymous block (once per device per site per 10 min, in-memory hashed key) |
| `GET /verdict?domain=` | the bilingual verdict page (web app) |
| `GET/POST /dns-query` | RFC 8484 DoH (`GUARD_DOH_ENABLED=1`, else 404). Blocked → NXDOMAIN (`zero` → 0.0.0.0/::, or `GUARD_VERDICT_IP`); others forwarded to `GUARD_UPSTREAM_DOH` (SERVFAIL if unreachable). 415 wrong content type, 413 > 4096 bytes. Not logged. |
| `GET /api/status`, `GET /api/mode` | runtime status / mode |
| `GET /api/healthz` | 200 `{ok:true}`, **503** if the database is unreachable (used by Docker healthcheck) |
| `GET /api/examples` | curated Sweep query presets `{check: [], numbers: [], sweep_web, sweep_maps}` (no sample findings) |
| `GET /api/guard/config` | Guard DNS hostname + whether NextDNS is configured (no secrets) |
| `GET /share` | serves the PWA (Web Share Target) |

## Authentication & administration

| Method & path | Role | Notes |
|---|---|---|
| (local) | — | With `LOCAL_OPEN_ACCESS=1` (dev only, never in production) a same-computer, non-proxied request without a session is the local admin `local`; `/api/auth/me` returns `{user:{username:"local", role:"admin", local:true}, csrf_token}`. |
| `POST /api/auth/login` | — | `{username, password}` → 200 `{user, csrf_token}` + cookie. 401 on bad credentials; 429 after `LOGIN_MAX_FAILURES` (5) failures per user **or** IP within 15 min. Constant-work dummy hash for unknown users. |
| `POST /api/auth/logout` | any | deletes the server session, clears cookie |
| `GET /api/auth/me` | — | `{user, csrf_token}` or 401 |
| `GET /api/admin/users` | admin | list users |
| `POST /api/admin/users` | admin | `{username, password ≥12, role}` → 201 (audited) |
| `POST /api/admin/users/{username}/active` | admin | `{active}`; disabling also revokes sessions (audited) |
| `GET /api/admin/audit?limit=` | admin | audit log |
| `POST /api/mode` | admin | compatibility only: `{mode: "live"}`; any other value → 422 (there is no demo mode) |
| `GET /api/readiness` | admin | configuration truth (no secrets): app_env, mode, trust policy loaded, registry version, trusted/total entries, portal user count, whether the official snapshot store exists |
| `GET /api/registry` | viewer | official registry entries with status/class/reviewer |

## Police Portal findings index

| Method & path | Role | Notes |
|---|---|---|
| `GET /api/portal/findings` | viewer | All findings (Checker, investigations, sweeps, radar), newest first. Query: `q` (domain, link, message text, reasons or `#id`), `tag` (SAFE/WARNING/MISLEADING/FAKE), `input_type` (url/text/domain), `source` (checker/investigation/sweep/crt/feeds/radar), `date_from`, `date_to` (YYYY-MM-DD, inclusive), `limit` ≤200, `offset`. → `{total, offset, limit, findings[], facets:{tag, input_type}}`. Reads never create or change findings. |
| `GET /api/finding/{id}` | public for radar findings; **viewer** for Checker and investigation findings | the complete stored analysis (identical to what the Checker showed) |

### Checker finding (stored detail, returned by `/api/check` and `/api/finding/{id}`)

`id, domain, verdict, score, reasons, source:"checker", created_at` plus:
`input_type` (url|text) · `submitted_input` (the URL, or the message with personal data removed) ·
`normalized_url` · `analyzed_url` (the link that drove the verdict) · `urls[]` (every link with its score) ·
`normalized`, `homograph` (URL analysis) · `tag`, `manual_review`, `trust_reasons`, `policy_version` ·
`domain_auth` · `gov_verification` · `signals[]` `{name, weight, reason, category, part, excerpt}` ·
`risk_score` · `scam_type` · `scanned_at` · `scan_status` (completed|partial) ·
`checks[]` `{id: engine|domain_authentication|official_verification, status: completed|not_applicable|unavailable|incomplete, detail}` ·
`precautions[]` (codes rendered by the UI in EN/AR) · `redactions` (counts of removed personal data) ·
`engine_version`. There is **no confidence value**: the engine does not produce one.

Signal `category`: government_impersonation, brand_impersonation, homograph, phishing, known_phishing,
fraudulent_offer, suspicious_message, suspicious_url, suspicious_infrastructure. Signal `part`: domain, path,
url, message, site.

Checker findings never enter the public feed, the SSE stream or the Guard DNS blocklist.

## Investigations (Police Portal)

| Method & path | Role | Notes |
|---|---|---|
| `POST /api/investigations` | investigator | `{url: 4–2048, page_text?: ≤8000}` → **201** stored finding (tag, authentication, verification evidence, signals, submitted URL, investigator, policy version). Non-http(s) / invalid URLs → 422. Audited. |
| `GET /api/investigations?limit=` | viewer | recent investigation findings |

## Sweeps (Search / Maps)

| Method & path | Role | Notes |
|---|---|---|
| `POST /api/sweep` | investigator | `{channel: "web"|"maps", lang: "en"|"ar", query_id? ≤64 | query? ≤200}` → **202** `{run_id, status: "running", ...}`; `?wait=true` → 200 with results. Free-text queries only if `SWEEP_ALLOW_ARBITRARY=1`. Rate limit `SWEEP_RATE_PER_MIN` (6) per client, `SWEEP_MAX_CONCURRENT` (2) global → 429. No engine configured → 503. In production, synthetic fixtures are disabled. |
| `GET /api/sweep?limit=` | viewer | runs (status, stage, source_kind, synthetic flag, error, timestamps) |
| `GET /api/sweep/{run_id}` | viewer | run + results (each result carries `tag` and reasons) |

Run `status`: `running → completed | failed`. FAKE/MISLEADING live results are stored as findings
(`source = sweep:web|sweep:maps`).

## Reports & AI Analyst

| Method & path | Role | Notes |
|---|---|---|
| `GET /api/reports` | viewer | reports with `tag` |
| `GET /api/reports/{id}` | viewer | |
| `POST /api/reports` | investigator | `{finding_id}` → 201; idempotent per finding; stores zero-PII evidence |
| `POST /api/reports/{id}/advance` | investigator | forward-only state machine; backwards → 409 |
| `GET /api/reports/{id}/export` | viewer | evidence pack: report, finding, policy & registry versions, disclaimer |
| `POST /api/report/{id}/analysis` | investigator | SSE; AI case summary built only from server-side grounded evidence; stored on the report. Provider chain Gemini → Groq → template. The AI never changes `tag`. |
| `POST /api/report/{id}/takedown` | investigator | draft takedown text, marked DRAFT for officer review |

## Timeouts

Outbound HTTP (`HTTP_TIMEOUT_S`, default 10 s); page render `RENDER_TIMEOUT_MS` (15 s); browser
client requests time out after 12 s and fall back to the offline tier, which never returns SAFE.
