# The live Checker — change record

Goal: a user submits a URL, domain or suspicious message → Daggers performs real analysis →
displays every result and its evidence → the exact same finding is automatically available in the
Police Portal. Live only: no demo mode, mock results, synthetic findings or simulated detection.

## 1. What the "final intelligence engine" upload contained

`11.zip` (`daggers-main`) is the team's live-only tree. Its detection core (`core/scorer.py`,
`claims.py`, `homograph.py`, the official-source verification engine) is **identical** to the
integrated build apart from comments, with one exception: `core/verdicts.py` maps `UNKNOWN → SAFE`.
That contradicts the central verdict policy ("unknown never SAFE"), so the integrated
`UNKNOWN → WARNING` mapping was kept.

Adopted from `daggers-main`: the live-only radar and vision modules (`radar/*`, `vision/*`, no
generated evidence stand-ins), live-only Search/Maps adapters (no fixture providers), the Guard
modules (`/api/guard/config`), adapter readiness in `/api/healthz`, Guard-stat aliases,
`/api/examples` as curated sweep queries only, test data moved to `backend/tests/ws2/data/`, the
"no demo/seed/fixture data in the runtime" gates, and `ops/verify_empty.py`. Its `main.py`,
`repo.py` and UI were **not** adopted: they lack the Police Portal login/roles/audit,
investigations and persisted findings, and its `/api/scan` skipped the trust policy entirely.

## 2. Engine improvements (`backend/app/core/`)

* `score_request` no longer discards the analysis. It returns every signal annotated with
  `category`, `part` (domain / path / url / message / site) and `excerpt` (the part of the input
  that triggered it), plus `normalized`, `homograph`, `analyzed_url` and every link found (`urls`).
* New `core/message.py` (pure, EN + AR + common Arabizi): requests for OTP / passwords / PIN /
  card or bank details; payment or fee demands; delivery lures; urgency and threats; brand or
  government impersonation (the text names an organisation but the link goes elsewhere, or it asks
  for credentials by message); link shorteners. Before this, a message without a prize/giveaway
  pattern was "no signals" — e.g. the classic customs-fee SMS.
* Verdict rules for messages: message signals add to the riskiest link's score. A message can
  only reach **FAKE** if it gives the victim a way to act (a link, or a request to send codes /
  details back); otherwise it is capped at WARNING (or MISLEADING for a prize claim). A bare
  "AED amount + organisation" match is reported once as a payment demand, not as a giveaway.
* New identity signal `identity.brand_embedded`: an organisation's name hidden in a hyphenated
  domain (`abudhabi-police-fines.top`, `adpolice-pay.top`) — previously only `.top` was flagged.
* Brand catalog: Emirates Post, DHL, Salik, TAMM and the Ministry of Interior added; government
  bodies marked `sector: government` so impersonation is reported as *government* impersonation.
  (FedEx was tried and removed: its short name caused a false look-alike match.)
* Phone-number checking was removed from the Checker and `/api/scan` (`kind` is `url` or `text`).
  `core/numbers.py` remains only because the Maps sweep scores business-listing phone numbers.
* There is **no confidence value**: the engine does not compute one, so none is shown.

## 3. Checker → database → Police Portal

* `POST /api/check` (`backend/app/api/check.py`, `backend/app/checker.py`, `Runtime.check`):
  validate → classify URL/domain vs message → normalise (https:// added to bare domains, tracking
  parameters and fragments removed; `user@host` kept as evidence) → engine → central verdict
  (registry authentication of the link that drove the verdict, official-claim verification) →
  checks list (what ran, what was not applicable, what could not complete) → precaution codes →
  personal data removed → stored with a request id in one transaction → the stored finding is
  returned and displayed.
* Official records come from the snapshot store filled by `make registry ARGS="fetch <id>"`;
  without retrieved records a claim is "not checked / not verifiable", never "verified".
* Duplicates: one request id per click on *Check it* (retries reuse it), and the same input from
  the same input while the Checker's own stored result is valid returns that stored result (`duplicate: true`, `cached: true`) — see CHECKER-ACCURACY.md §7. Portal reads never
  write.
* Failures: invalid input → 422 with a reason; engine failure → 503 `analysis_failed`, nothing
  stored; storage failure → 503 `persist_failed`, the analysis is shown marked **not saved**. The UI
  never shows a verdict for a failed check.
* Privacy: Checker findings are visible only to signed-in portal users, are never in the public
  feed/stream, and never feed the Guard DNS blocklist automatically.
* Police Portal: new **All findings** index (`GET /api/portal/findings`) — search by domain, link,
  message text or `#id`; filter by verdict, input type, source and date range; paging; counts by
  verdict. The finding page and the Checker use the **same renderer** (`web/js/components/analysis.js`),
  so they show the identical verdict, score, signals (expandable: what, why, which part, excerpt),
  checks, authentication, official verification, links and precautions.

## 4. UI changes

* Checker: one field for a link or a whole message, character counter, client + server validation
  messages, honest progress (the stages are listed; nothing is shown as done until the stored result
  returns), complete result, "Saved as finding #N", *Open in the portal* (signed in), *Check
  something else*, clear errors, works on mobile and in Arabic (RTL).
* Removed: the Numbers page and navigation, the Checker's phone-number link, the LIVE/DEMO toggle,
  the offline rules "verdict", all fixtures and bundled sample evidence, the client-side AI
  "fallback" summary, the fabricated finding timeline and the hard-coded "97% clone of ADCB" caption,
  the timer-driven fake row-by-row sweep scoring.
* Fixed: a connectivity change re-rendered the current page, wiping the user's input and any error
  shown; strings claiming reports are "filed with Abu Dhabi Police" now say "filed in the Police Portal".

## 5. Modified files (relative to the previous integrated build)

**Added** — `backend/app/api/check.py`, `backend/app/api/examples.py`, `backend/app/checker.py`,
`backend/app/core/message.py`, `backend/app/main_errors.py`, `web/js/components/analysis.js`,
`backend/tests/test_checker.py`, `backend/tests/ws2/data/*` (moved test data), `backend/tests/ws3/__init__.py`,
`ops/verify_empty.py`, `docs/CHECKER.md`.

**Changed** — backend: `main.py`, `config.py`, `catalog.py`, `core/scorer.py`, `core/brands.yaml`,
`core/numbers.py`, `db/repo.py`, `db/schema.sql`, `reports/builder.py`, `channels/scoring.py`,
`channels/search.py`, `channels/maps.py`, `channels/guard.py`, `api/scan.py`, `api/health.py`,
`api/system.py`, `api/sweep.py`, `api/guard.py`, `radar/{crt,enrich,feeds,pipeline}.py`,
`vision/{diff,gallery,render}.py`. Frontend: `web/index.html`, `web/sw.js`, `web/css/components.css`,
`web/js/api.js`, `web/js/app.js`, `web/js/i18n/{i18n.js,en.json,ar.json}`,
`web/js/views/{check,finding,portal,sweep,feed}.js`. Tests: `conftest.py`, `test_api_contracts.py`,
`test_integration.py`, `test_numbers.py`, `test_scorer.py`, `ws2/{__init__,helpers,test_api_ws2,test_channels,test_official_scenarios,test_retrieval,test_scan_integration}.py`.
Ops/docs: `Makefile`, `Dockerfile`, `.env.example`, `ops/check_i18n.py`, `ops/e2e_portal.mjs`,
`README.md`, `docs/{API,ARCHITECTURE,DEPLOYMENT,SECURITY,INTEGRATION-REPORT,TESTING-REPORT,RUNBOOK,WS2,WS2-README}.md`,
`extension/README.md`.

**Removed** — the backend seed package, the web fixture folder, `web/evidence/` (bundled sample screenshots), `ops/demo/`,
`backend/app/channels/fixtures/`, `backend/app/channels/official/fixtures/` (moved to tests),
`backend/app/channels/ws2.env.example`, `web/js/views/number.js`, `web/js/views/portal_fallback.js`,
`backend/tests/ws3/test_contracts.py` (tested fixtures), `ops/{check_ui,check_offline,check_a11y}.mjs`
(demo-story gates), `ops/{dev.sh,serve_web.py,test_all.sh,setup.sh,setup_browser.sh,checklist.md}`,
`docs/{HANDOFF-WS3,START-HERE-WS3}.md`.

## 6. Run it

```bash
make bootstrap                    # add PIP_INDEX=https://pypi.org/simple behind a private mirror
make dev                          # http://localhost:8000/#/check  ·  portal: http://localhost:8000/#/portal
```

With `make dev` the Police Portal opens directly on the same computer, with no account or login
(`LOCAL_OPEN_ACCESS`, development only, off in production; see docs/SECURITY.md). For access from
other computers or in production, create accounts: `make user U=alice R=investigator`.

## 7. Known limitations and unresolved issues

* **Not run on real FastAPI here.** FastAPI could not be installed in the build environment; the
  backend tests and the live browser test ran on the repository's FastAPI-compatible harness over
  real Starlette/uvicorn. Run `make check` and `make e2e` on a machine with the pinned dependencies.
* **SAFE needs an approved registry entry**: every shipped entry is pending until a named reviewer runs `make approve-verified` — see [GOVERNMENT-SAFE.md](GOVERNMENT-SAFE.md).
* **Official claim verification needs retrieved records** (`registry fetch`), which needs network
  access to the approved sites; this was not exercised here (no network), so government claims in
  Checker messages are currently reported as not verifiable / not checked.
* **The Checker does not visit submitted sites** (no screenshots, page content, certificate or
  WHOIS lookups at check time) — by design, to avoid fetching attacker-controlled URLs. Radar
  enrichment/rendering exists but is not run for Checker submissions.
* **Rule-based detection**: deterministic patterns can miss new wording and can flag benign text
  (e.g. a legitimate brand-named domain with a login path). Message rules cover English, Arabic and
  common Arabizi; other languages get URL analysis only.
* **Signal explanations** ("why") come from the engine in English; titles, categories, checks and
  precautions are translated.
* **Redaction is pattern-based**: phone, e-mail, Emirates ID, IBAN and card numbers are removed;
  names and street addresses are not.
* **Abuse**: the Checker is public; the per-client rate limit is the only quota.
* **Portal search** filters the most recent 2,000 findings per query in the application layer; a
  larger deployment needs indexed SQL filtering (Postgres).
* Arabic UI copy was written for this change and should be reviewed by a native speaker.
