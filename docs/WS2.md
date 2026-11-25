# Daggers — Workstream 2: Shield & Channels

> **Integrated build note:** the WS1 patches described below have been applied in this repository and the `patches/` folder removed. See `docs/INTEGRATION-REPORT.md`.


WS2 adds the official UAE source registry and government-claim verification engine, the WS2 trust
policy, Search and Maps channel adapters, the Sweep API, Guard blocklist generation, and the Chrome
extension. It calls the WS1 brain in-process and changes **no** WS1-owned file; the WS1 changes it
needs are delivered as patches in `patches/ws1/`.

> Unofficial hackathon prototype. Nothing here is an official UAE Police or government product.

---

## 1. Status at a glance

| Area | Implemented | Tested here | Integration pending | Not done |
|---|---|---|---|---|
| Trust policy (SAFE/WARNING/MISLEADING/FAKE) | ✅ `channels/trust_policy.py` | ✅ | `/api/scan` needs WS1 patch 0001+0002 | — |
| Official registry + approval CLI | ✅ `channels/official/` | ✅ | — | No entry approved yet (needs a human reviewer) |
| Claim verification engine (6 statuses) | ✅ pure, deterministic | ✅ 14 scenarios + invariants | — | Semantic/AI matching (optional extension) |
| Evidence + snapshots | ✅ content-addressed, append-only | ✅ | — | — |
| Secure fetcher (SSRF-safe, robots, RSS) | ✅ stdlib | ✅ with fake DNS/HTTP | — | **Never run against a live site** |
| U.AE directory discovery | ✅ pending-only | ✅ synthetic fixture | — | **Live page structure not validated** |
| Search (Serper → DDG → fixture) | ✅ | ✅ fixtures + fake providers | — | **Live providers not exercised** |
| Maps (fixture-first, Google Places) | ✅ | ✅ fixtures | — | **Live Places not exercised** |
| Sweep API `POST /api/sweep`, `GET /api/sweep/{id}` | ✅ | ✅ service; router via stub only | Persistent storage needs WS1 patch 0004 | — |
| Guard `blocklist.txt`, `sync-status`, NextDNS script | ✅ | ✅ logic; router via stub only | — | **NextDNS API not exercised** |
| Chrome MV3 extension | ✅ | ✅ Node tests (logic + mocked worker) | Shows SAFE only after WS1 patch | Real-browser/Google-DOM run; Web Store publication |

"Router via stub only": FastAPI and httpx are not installed in the build environment and package
installs were blocked, so the HTTP routers were exercised by calling the handlers through a minimal
FastAPI stand-in. `backend/tests/ws2/test_api_ws2.py` contains real `TestClient` tests that are
**skipped** here and must be run where `make bootstrap` works.

---

## 2. Verdict and website-trust policy

Implemented once, in `backend/app/channels/trust_policy.py`. Four layers are computed and reported
**separately** on every result:

1. `domain_auth` — registry authentication of the exact host (`AUTHENTICATED`, `UNLISTED`, `PENDING`,
   `REVOKED`, `EXPIRED`, `NOT_CHECKABLE`, `INDEPENDENT_MEDIA`)
2. `gov_verification` — claim verification (`VERIFIED`, `CONTRADICTED`, `NOT_VERIFIABLE`,
   `SOURCE_UNAVAILABLE`, `SOURCE_EXPIRED`, `CONFLICTING_SOURCES`) or `null` when no government claim
3. maliciousness — WS1 `verdict`/`score`/`reasons`, untouched
4. `tag` — the final user-facing verdict

| Situation | Tag |
|---|---|
| Approved, fresh Class A/B domain, no suspicious content, no unverified government claim | **SAFE** |
| Unknown / unlisted domain | WARNING |
| Pending, revoked, or expired registry entry | WARNING |
| Authenticity cannot be checked (IP host, `user@host`, plain HTTP, odd port, invalid name) | WARNING |
| Approved Class C (independent media) domain | WARNING (not an official source) |
| Unauthenticated site, government claim `CONTRADICTED` | MISLEADING |
| Unauthenticated site, `NOT_VERIFIABLE` after relevant approved sources **were checked** | MISLEADING |
| Unauthenticated site, `NOT_VERIFIABLE` because **no approved source covers** the claim | WARNING + manual review |
| `SOURCE_UNAVAILABLE`, `SOURCE_EXPIRED`, `CONFLICTING_SOURCES` | WARNING + manual review |
| WS1 `MISLEADING` (its claim rule) on an unauthenticated site | MISLEADING |
| WS1 `MALICIOUS` (confirmed phishing/impersonation/fraud) on an unauthenticated site | **FAKE** |
| Authenticated domain with flagged content, an unverified/contradicted claim (e.g. UGC), or WS1 `MALICIOUS` | WARNING + manual review — never auto-FAKE, never blocked |

Rules that follow from the table: `UNKNOWN` never becomes SAFE; absence of signals is not
authenticity; unknown sites are not automatically FAKE; a private business outside the registry gets
WARNING, not FAKE. On an authenticated domain, WS1 signals that come **only from the domain name**
(`lexical.*`, `identity.*`, `homograph.*`) are superseded by registry authentication of that exact
host — e.g. WS1's typo heuristic rates `news` ≈ `dewa` (distance 2). Content, infrastructure and feed
signals are never superseded.

**Scope today:** WS2 surfaces (Search, Maps, Sweep, the adapter used by `/api/scan` after the patch)
enforce this. **`POST /api/scan` does not enforce it until WS1 merges patches 0001 and 0002**; until
then WS1's own table maps `UNKNOWN → SAFE`. The extension never shows SAFE against an unpatched
backend (it shows `UNVERIFIED`).

**Production consequence:** every seeded registry entry is `pending`, so nothing is SAFE until a
reviewer approves entries. That includes banks/telcos on WS1's brand allowlist (e.g. `adcb.ae` →
WARNING): the allowlist prevents impersonation scoring but does not authenticate a government source.

---

## 3. Official UAE source registry (`backend/app/channels/official/`)

| File | Role |
|---|---|
| `models.py` | dataclasses, status vocabularies, timestamps |
| `registry.py` | YAML loading, strict validation, host authentication, entity resolution, approval/revocation |
| `normalize.py` | Arabic diacritics/tatweel/Alef/Ya, Arabic-Indic digits, EN/AR dates, amounts → AED |
| `extract.py` | lexicon loader, claim extraction (entity, category, concepts, amounts, dates, language) |
| `compare.py` | deterministic claim ↔ record comparison |
| `verify.py` | source selection + verification statuses + evidence (pure) |
| `fetch.py` | secure retrieval layer |
| `snapshots.py` | content-addressed append-only store |
| `discover.py` | U.AE directory → pending candidates |
| `cli.py` | admin CLI |
| `registry.yaml`, `lexicon.yaml` | data |
| `fixtures/` | SYNTHETIC registry, records, directory page |

Each entry: organization; EN/AR/transliterated aliases; exact domains; explicit subdomain policy
(`exact` | `listed` + `allowed_subdomains` | `any`); source class; jurisdiction; authority scope;
categories; languages; approved source URLs (`kind`, `terms_reviewed`); provenance; status; reviewer;
`verified_at`; `max_age_days`; optional `brand_token`.

**Trust:** only `approved` + named reviewer + `verified_at` within `max_age_days` authenticates.
Matching is exact on the punycode host; public suffixes (`gov.ae`, `ae`, `abudhabi`, …) are rejected as
registry domains, so nothing is trusted for ending in `.gov.ae`. `u.ae`, `uaepass.ae` and
`mediaoffice.abudhabi` are ordinary explicit entries.

**Seeded candidates (all `pending`, no reviewer, no dates):** U.ae portal, UAE PASS, Abu Dhabi Police,
Dubai Police, ICP, MoHRE, RTA, DEWA (Class A, from the brief and the government-type rows of
`brands.yaml`, read-only); WAM, Abu Dhabi Media Office, Government of Dubai Media Office (Class B);
The National, Khaleej Times, Gulf News (Class C). Source URLs are homepages with
`terms_reviewed: false`, so the fetcher refuses them until a reviewer records real feed/page URLs.

### Approving entries

```bash
python -m backend.app.channels.official.cli list --status pending
python -m backend.app.channels.official.cli show wam
python -m backend.app.channels.official.cli approve wam --reviewer "Full Name"     # interactive confirm
python -m backend.app.channels.official.cli revoke wam --reviewer "Full Name" --reason "domain changed"
python -m backend.app.channels.official.cli validate
python -m backend.app.channels.official.cli authenticate https://www.wam.ae/en
python -m backend.app.channels.official.cli verify "ICP announces visa amnesty" --records records.json
python -m backend.app.channels.official.cli discover --html saved_directory.html --source-url https://u.ae/en/Help/The-Government [--write]
python -m backend.app.channels.official.cli --snapshots backend/data/official_snapshots fetch wam   # live; approved only
```

Before approving, the reviewer confirms domains, class, jurisdiction and scope against the entity's own
channels, and edits `source_urls` (set `terms_reviewed: true` only after reading robots.txt/terms).
Approval stamps the real current time; the file is validated and replaced atomically. Synthetic entries
cannot be approved via the CLI. The running server loads the registry once per process: restart the backend
after approving or revoking entries.

### Source classes

* **A — primary authorities** decide service, legal, fee, benefit, eligibility and announcement claims.
* **B — official media** can verify that an announcement was published. For *regulated* categories
  (`fees`, `financial_aid`, `immigration`, `traffic`, `giveaway`) a B record alone yields
  `NOT_VERIFIABLE` (A checked, silent) or `SOURCE_UNAVAILABLE` (A not checked) while the responsible
  Class A authority is in the registry. B may contradict. A disagreeing B record never overrides A.
* **C — independent media** is `supporting_context` only; it never authenticates a domain or decides a status.

---

## 4. Verification engine

Pipeline: extract claim → identify entity (EN/AR/transliterated aliases; organization names are
removed before topic analysis so "Ministry of Social *Support*" is not a "support" topic) → classify
via the bilingual lexicon → select approved, fresh sources by entity, jurisdiction and authority scope
→ use pre-fetched records → compare → status + evidence.

Comparison is deterministic: same entity/authority **and** same subject (a specific concept such as
`golden_visa` or `amnesty` must match when present; broad ones like `visa` are not enough); then
stance (a record that denies/warns contradicts an affirming claim) and amounts (AED, after
normalization). Newer records from an equal-or-higher class supersede older disagreeing ones; equal-date
disagreement between Class A sources is `CONFLICTING_SOURCES`.

Honesty rules: an unreachable source is listed in `unchecked_sources` with "not checked"; a retrieval
failure can never yield `VERIFIED`; records whose URL is outside the entry's domains are ignored;
evidence older than 30 days is not used (`SOURCE_EXPIRED`); "not found on official channels" is never
produced by WS2 unless sources were actually checked.

### `gov_verification` object (WS3 contract)

```json
{
  "status": "CONTRADICTED",
  "coverage": "checked | not_checked | no_relevant_source",
  "claim": {"canonical": "...", "entity_ids": ["icp"], "entity_names": ["..."], "generic_government": true,
            "categories": ["immigration"], "concepts": ["amnesty", "visa"], "amounts_aed": [250.0],
            "dates": ["2026-12-31"], "language": "en"},
  "evidence": [{"role": "decisive | superseded | related | supporting_context",
                "comparison": "supports | contradicts | related",
                "source_class": "A", "entry_id": "icp", "organization": "...",
                "source_url": "https://...", "published_at": "2026-11-10T06:00:00Z | null",
                "retrieved_at": "2026-11-20T08:00:00Z", "excerpt": "verbatim sentence from the record",
                "content_hash": "sha256", "detail": "source denies or warns against this claim",
                "synthetic": false}],
  "checked_sources": ["icp"], "unchecked_sources": ["wam"], "relevant_sources": ["icp", "wam"],
  "notes": ["WAM: no retrieved records available; not checked"],
  "evidence_id": "gv_<24 hex>", "registry_version": "reg_<16 hex>",
  "policy_version": "ws2-trust-1.0", "verified_at": "2026-11-24T12:00:00Z"
}
```

`evidence_id = "gv_" + sha256(canonical claim | sorted record content hashes | registry version | policy version)[:24]`.
Excerpts are verbatim slices of retrieved text; `published_at` is `null` when the source gave none.

---

## 5. Retrieval, snapshots, discovery

`SecureFetcher.fetch(entry_id, url)` only fetches URLs listed in an approved, fresh entry with
`terms_reviewed: true`; HTTPS, default port, no credentials; resolves DNS itself and rejects any
non-global address (private, loopback, link-local, CGNAT, multicast, reserved, IPv4-mapped, …) **on
every redirect hop**, then connects to the validated IP with SNI + certificate verification for the
hostname (no DNS-rebinding window); redirects must stay inside the entry's domains (max 3); connect
timeout 5 s, total deadline 15 s, 2 MB cap, content-type allowlist; one request per host per 10 s;
robots.txt per RFC 9309 (4xx = allowed, 5xx/unreachable = disallowed); XML with DOCTYPE/ENTITY
rejected before parsing; HTML reduced to text without executing scripts; RSS/Atom items pointing off
the entry's domains are dropped. User-Agent `Daggers-Research/1.0`. Every failure returns
`ok: false` + `error_code` and becomes an `error` record.

`SnapshotStore` writes `objects/<sha[:2]>/<sha>.txt` with `O_EXCL` (never overwritten), appends to
`index.jsonl` with fsync, verifies hashes on read, and exposes `provider()` for `ShieldScorer`.
Default location `backend/data/official_snapshots/` (git-ignored).

Discovery parses anchors and section headings of a saved directory page into **pending** candidates
(skipping the directory host, social networks, IPs, plain HTTP and credentialed links) and merges them
without touching existing entries. Class, jurisdiction and scope on candidates are labelled
unreviewed guesses. Live U.AE parsing has not been validated.

---

## 6. Channels

**Shared scoring** — `channels/scoring.py::ShieldScorer` is the only entry point: WS1
`core.scorer.score_url` → registry authentication → claim verification → trust policy. No competing
scorer exists.

**Search** — `channels/search.py`. Provider chain: Serper (if `SEARCH_LIVE_ENABLED=1` and
`SERPER_API_KEY`), DuckDuckGo HTML (if `SEARCH_LIVE_ENABLED=1`), fixtures. Organic results only (Serper
`organic`, DDG ad redirects dropped). Redirect unwrapping (Google `/url?q=`, DDG `uddg=`), tracking
parameter removal, punycode hosts, registrable domain, dedupe (`www`, trailing slash, scheme), PII
redaction of titles/snippets. `source_kind` is `live`, `cached` (15-min in-memory cache of live
answers), `unconfigured` or `unavailable`; the running app has no fixture provider. Result URLs are scored,
never fetched.

**Maps** — `channels/maps.py`. Fixtures by default; Google Places Text Search only with
`MAPS_LIVE_ENABLED=1` + `GOOGLE_PLACES_API_KEY`. Per listing: `listing` (third-party listing evidence:
provider, `provider_place_id`, `retrieved_at`, `is_synthetic`, `evidence_type: third_party_listing`) and
separate `checks.identity` (`no_official_claim` | `consistent` | `mismatch` | `not_assessable`),
`checks.website` (shared scorer), `checks.phone` (WS1 `numbers.check_number`). Missing website/phone is
`not_provided` and never fraud evidence; such listings are WARNING because they cannot be
authenticated. Google Places content is not persisted by WS2 beyond the in-memory sweep store; check
Google's terms before enabling persistent storage of Places fields.

---

## 7. Sweep API (WS3 contract)

`POST /api/sweep`

```json
{"channel": "web | maps", "lang": "en | ar", "query_id": "web-adpolice-fines", "query": null}
```

Resolution: `query_id` → that default; else `query` equal to a default → allowed; else free text only
with `SWEEP_ALLOW_ARBITRARY=1` (3–120 chars, refused with 422 if it contains an email, phone,
Emirates ID, IBAN, card or passport number); else the first default for the channel/lang from
`backend/app/channels/queries.yaml`. Rate limit `SWEEP_RATE_PER_MIN` (6) per client IP → 429; at most
`SWEEP_MAX_CONCURRENT` (2) sweeps → 503. Errors: 403 (arbitrary disabled), 404 (unknown `query_id`),
422 (validation).

Response (also `GET /api/sweep/{id}`; 404 if unknown):

```json
{
  "id": 1, "query": "...", "query_id": "web-adpolice-fines", "lang": "en", "channel": "web",
  "engine": "serper | duckduckgo | google_places | fixture", "cached": false,
  "source_kind": "live | cached | fixture", "synthetic": true, "created_at": "...Z",
  "store": "memory-temporary | sqlite",
  "counts": {"SAFE": 0, "WARNING": 2, "MISLEADING": 1, "FAKE": 2},
  "errors": ["serper: ProviderError"],
  "results": [{
    "position": 1, "url": "https://...", "title": "...", "snippet": "...",
    "verdict": "MALICIOUS", "score": 0.8, "reasons": ["..."], "finding_id": null,
    "tag": "FAKE", "manual_review": false, "domain_auth": {"...": "see §2"},
    "gov_verification": null, "trust_reasons": ["..."], "blockable": true,
    "source_kind": "fixture", "maps": null
  }]
}
```

The first eight row fields are exactly the `sweep_results` columns; the rest are additive. Maps rows
set `maps: {"listing": {...}, "checks": {...}}`; `url` is the website or `maps:<provider>:<place_id>`.
`GET` returns `query_id: null` (the schema has no column for it). A `sweep` SSE event
`{id, channel, query_id, source_kind, counts, created_at}` is published through `runtime.publish`.

**Storage:** `InMemorySweepStore` is **temporary** (lost on restart, max 200 runs). With WS1 patch 0004
the router automatically uses `RepoSweepStore` (SQLite).

---

## 8. Guard

Endpoints added (only these two): `GET /api/guard/blocklist.txt?format=hosts|domains`,
`GET /api/guard/sync-status`. Source is WS1's existing Guard feed (`runtime.guard_rows()`, the data
behind `/api/guard/feed`). Blocked: `MALICIOUS` only; valid DNS names; flagged within
`GUARD_MAX_AGE_DAYS` (30) and not future-dated; never registry or WS1-allowlisted domains. Excluded rows are counted by
reason (`not_malicious`, `invalid_domain`, `expired`, `undated`, `duplicate`, `official_or_registry`).
Feed failure keeps the last good list and reports `status: "stale"`.

Guard statistics shape (WS3): WS1's `/api/guard/stats` stays the source for `blocked_domains` /
`blocked_hits`. WS2's `sync-status`:

```json
{"status": "never | ok | stale | error", "source": "guard_feed", "mode": "live",
 "last_attempt_at": "...", "last_success_at": "...", "last_error": null, "consecutive_failures": 0,
 "rows_in": 3, "blocked_domains": 3, "excluded": {"not_malicious": 0, "...": 0}, "max_age_days": 30,
 "policy": "MALICIOUS only; official/registry domains never blocked",
 "nextdns": {"push": "manual script guard/sync_nextdns.py (not run by the server)",
             "block_events_measured": false, "note": "..."}}
```

NextDNS: `guard/sync_nextdns.py` (dry run by default; `--apply` with `NEXTDNS_API_KEY` and
`NEXTDNS_PROFILE`). WS2 does not measure block events and never claims it did; NextDNS free-tier
analytics are limited and are not read. See `guard/README.md`.

---

## 9. Chrome extension

See `extension/README.md`. MV3; `storage` permission only; content script on Google search pages;
organic results only; debounced `MutationObserver`; one label per link; backend tag only; SAFE only
when `tag == "SAFE"` and `domain_auth.authenticated`; failures → `NOT CHECKED` (grey); session-only
cache; only the result URL without query/fragment is sent. Not on the Chrome Web Store.

---

## 10. WS1 integration (requires WS1 approval)

All patches apply cleanly to the received WS1 tree (`patch -p1 --dry-run`) and were tested on a
patched copy: WS1 pure tests 73/73, WS2 tests 90/90, repository sweep round-trip OK. The FastAPI-level
WS1 tests could not be executed here (FastAPI/httpx not installable).

| Patch | Files | Why |
|---|---|---|
| `0001-scan-applies-ws2-trust-policy` | `backend/app/main.py` | `Runtime.scan` calls `ShieldScorer.apply_to_scan_result` **before** returning any tag. WS1 fields unchanged; adds `tag`, `manual_review`, `domain_auth`, `gov_verification`, `trust_reasons`, `blockable`, `policy_version`. If WS2 fails to load or raises, it fails closed (tag never SAFE). |
| `0002-ui-tag-unknown-is-not-safe` | `core/verdicts.py` | `UI_TAGS[UNKNOWN]` and the default → `WARNING`, so no WS1-only path can say SAFE. |
| `0003-claims-honest-unverifiable-reason` | `core/claims.py` | Reason text no longer says "not found on official channels" (nothing was checked); now "not confirmed by an authenticated official source". |
| `0004-repo-sweep-persistence` | `db/schema.sql`, `db/repo.py` | `create_sweep_run`, `add_sweep_results`, `get_sweep_run`; additive `sweep_results.detail` JSON column with an in-place `ALTER TABLE` for existing databases. |
| `0005-tests-ws2-landed` | `tests/test_api_contracts.py`, `tests/test_claims.py` | Test updates below. |

Apply: `patch -p1 < patches/ws1/000N-*.patch` from the repository root (in order).

**Existing WS1 tests affected**

* Break as soon as WS2 files exist (independent of the patches) — **the two tests**:
  `test_optional_routers_are_skipped_without_ws2_ws3` (expects `sweep` skipped; it is now mounted) and
  `test_scope_audit_no_ws2_ws3_or_redundant_files` (forbids `guard/`, `channels/`, `extension/`,
  `api/sweep.py`, `api/guard.py`).
* Additionally need updating **only if** patches 0001/0003 are merged: `test_scan_url_contract_and_evidence_lookup`
  and `test_scan_number_and_text_claims` (exact key sets; patch uses `SCAN_KEYS | WS2_SCAN_KEYS`) and
  `test_claims.py::test_english_giveaway_with_amount_and_entity` (reason text). Patch 0005 also adds
  `test_unknown_url_is_never_tagged_safe`.

**`ScanResult` field proposal** (additive; WS1 keys keep their meaning):

| Field | Type | Meaning |
|---|---|---|
| `tag` | `SAFE\|WARNING\|MISLEADING\|FAKE` | final user-facing verdict — every surface displays this |
| `manual_review` | bool | analyst review recommended |
| `domain_auth` | object \| null | §2 layer 1 (`status`, `authenticated`, `host`, `entry_id`, `organization`, `source_class`, `reason`, `registry_version`) |
| `gov_verification` | object \| null | §4 |
| `trust_reasons` | string[] | why this tag (WS1 `reasons` stay the evidence list) |
| `blockable` | bool | Guard-eligible (confirmed FAKE on an unauthenticated domain) |
| `policy_version` | string | `ws2-trust-1.0` |

**Zero-PII validator contract.** WS1's `validate_zero_pii` rejects keys containing tokens such as
`name`, `phone`, `address`, `input`, `message`. Therefore: reports keep carrying the **Finding object
only**; never embed sweep rows, `maps.listing` (has `name`/`phone`/`address`) or `gov_verification`
(has `entity_names`/`organization`) in a report. To link verification to a report, carry
`evidence_id` (a `gv_…` string) only. WS2 inputs: Sweep refuses PII queries; titles/snippets/listing
names/addresses are redacted; the extension sends only the result URL; `/api/scan` input is not
stored by WS2.

---

## 11. WS3 integration notes

* Display `tag`; never derive a label from `verdict` alone. If `tag` is absent (unpatched backend),
  do not show SAFE.
* Distinguish authenticated sources with `domain_auth.authenticated === true` (and `source_class`
  A/B). Show `domain_auth.status` for everything else (`PENDING` ≠ fake, `INDEPENDENT_MEDIA` ≠ official).
* Show `gov_verification.status`, `coverage`, decisive evidence (`role == "decisive"`, with
  `source_url`, `published_at` or "date not given", `retrieved_at`, `excerpt`), `unchecked_sources`
  as "not checked", and mark Class C evidence as supporting context. Mark `synthetic: true` evidence
  as test data (the integrated app has no fixture provider: unconfigured sweeps fail honestly).
* Sweep/Guard shapes: §7 and §8.

---

## 12. Security review and limitations

Reviewed: SSRF/private-network (fetcher IP checks per hop + pinned connect; provider HTTP limited to
three fixed hosts, no redirects); open redirects (redirector unwrapping only produces a URL to score,
never to fetch); unsafe URL parsing (strict parse, credentials/odd schemes rejected); domain spoofing
and homographs (exact punycode match, no confusable folding for trust, `user@host` and suffix tricks
tested); malformed registry entries (strict validator; atomic writes; invalid files never written);
injection (no SQL in WS2; YAML `safe_load`; XML DTDs rejected; no HTML injected in the extension);
excessive requests (sweep rate limit + concurrency cap; fetcher per-host interval; extension
concurrency 4 and caching); sensitive-data leakage (PII refusal/redaction; extension sends URL path
only; no secrets in extension code — asserted by test); insecure responses (no input echo stored);
untrusted HTML (stdlib parsers, scripts skipped); extension permissions (`storage` only, runtime
per-origin host permission); caching (session-only; failures cached 60 s as errors, never as verdicts);
stale evidence (30-day evidence window, registry `max_age_days`); verdict escalation (authenticated
domains never auto-FAKE or blocked; Guard blocks MALICIOUS only).

Known limitations:

* No registry entry is approved, so in production nothing is SAFE and government claims are mostly
  `NOT_VERIFIABLE (no_relevant_source)` → WARNING until reviewers approve entries and fetch sources.
* The fetcher, live search/maps providers, U.AE discovery and NextDNS script have **not** been run
  against live services from this environment.
* Matching is lexical. Paraphrases outside the lexicon, unusual Arabic spellings, or claims without an
  amount/denial cue may be `NOT_VERIFIABLE` rather than `VERIFIED`/`CONTRADICTED`.
* The sweep rate limiter keys on the connecting IP; behind a proxy (e.g. HF Spaces) that may be the
  proxy, so the global concurrency cap is the effective protection. In-memory limiter/stores are
  per-process.
* Google DOM selectors can drift; unmatched results simply get no label.
* Inherited from WS1 (observed, not changed): typo heuristics can flag ordinary words (`noor`≈`noon`,
  `news`≈`dewa`) as SUSPICIOUS on unknown domains (→ WARNING, never SAFE anyway).

---

## 13. Running WS2

```bash
make bootstrap && make dev                         # backend on :8000 (live only)
curl -s -X POST localhost:8000/api/sweep -H 'Content-Type: application/json' -d '{"channel":"web"}'
curl -s localhost:8000/api/sweep/1
curl -s localhost:8000/api/guard/blocklist.txt
curl -s localhost:8000/api/guard/sync-status

# tests
python -m pytest -q --confcutdir=backend/tests/ws2 backend/tests/ws2   # or: python -m unittest discover -s backend/tests/ws2 -t .
node --test extension/tests/core.test.js
```

WS2 needs no packages beyond WS1's `requirements.txt` (stdlib HTTP; PyYAML already pinned).
Environment switches: `backend/app/channels/ws2.env.example`.
