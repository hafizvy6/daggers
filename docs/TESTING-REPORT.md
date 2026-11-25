# Daggers — Testing report (live Checker build)

Final run: 2026-11-25, on the code in this ZIP. Every number below is from a run that was
actually executed. Nothing listed under "not executed" was run.

## 1. Environment and caveat

* Python 3 + pytest. **FastAPI could not be installed** (no package network). The backend tests
  use `backend/tests/_compat/fastapi/`, a small FastAPI-compatible layer on **real Starlette and
  Pydantic**, only when real FastAPI is missing. The live server for the browser test ran the same
  way under **real uvicorn**. → Re-run `make check` and `make e2e` with the pinned dependencies.
* Node 22; Playwright with Google Chrome for the browser test.
* No Docker daemon, no outbound network, no API keys.

## 2. Results

| Suite | Command | Result |
|---|---|---|
| Backend: unit + integration + API | `make test` | **450 passed**, 14 subtests passed, 0 failed |
| — of which the live Guard (`test_guard_live.py`) | `pytest backend/tests/test_guard_live.py` | **26 passed** (eligibility, Checker/Radar → Guard, all endpoints, DoH wire format, NextDNS + AdGuard Home against mocked APIs, access-log privacy) |
| — of which government SAFE / registry (`test_gov_safe.py`) | `pytest backend/tests/test_gov_safe.py` | **26 passed** |
| — of which independent Checker + result store (`test_checker_independent.py`) | `pytest backend/tests/test_checker_independent.py` | **9 passed** (every Portal read blocked) |
| — of which Checker accuracy 1–5 (`test_accuracy.py`) | `pytest backend/tests/test_accuracy.py` | **85 passed** (fake RDAP / web / DNS; real PSL + registry) |
| — of which reputation SAFE path (`test_site_reputation.py`) | `pytest backend/tests/test_site_reputation.py` | **34 passed** (ranking file is test data) |
| — of which the live Checker scenarios | `pytest backend/tests/test_checker.py` | **36 passed** (34 scenarios + 2 local-access tests) |
| Direct portal access without login (`LOCAL_OPEN_ACCESS=1`, real Chrome) | manual script | Checker → portal row → finding page → investigation (CSRF via `/api/auth/me`) all worked |
| Chrome extension logic | `make test-ext` | **10/10 passed** |
| i18n / design / no-demo-data gate | `python3 ops/check_i18n.py` | clean — 656 keys × 2 languages |
| JS syntax gate | `node ops/check_syntax.mjs` | 20 ES modules parse |
| Fresh install contains no product data | `make verify-empty` | ok |
| **Browser acceptance test** (live server, real Chrome) | `make e2e` | **35/35 checks passed** |
| **Government SAFE browser test** (live server, registry copy approved/revoked while running) | `make e2e-gov` | **22/22 checks passed** — details in [GOVERNMENT-SAFE.md](GOVERNMENT-SAFE.md) §5 |
| **Checker restore after closing browser + restarting the program** | `make e2e-restore` (2 phases) | **8/8 checks passed** |
| **Guard browser test** (live server, real Chrome: SSE update, test bar, verdict page EN/AR, one count per visit) | `make e2e-guard` | **19/19 checks passed** |
| **Guard smoke** (real uvicorn + curl, `GUARD_DOH_ENABLED=1`) | see §Guard below | stats, lists + ETag, `/api/check` → listed, `/verdict`, sync + 429 cooldown, DoH GET/POST blocked → NXDOMAIN, clean → SERVFAIL (no upstream in the sandbox), nothing in the access log |
| **Reputation SAFE browser test** (live server, TEST ranking file installed/removed while running) | `make e2e-rep` | **20/20 checks passed** — details in [GOVERNMENT-SAFE.md](GOVERNMENT-SAFE.md) §8 |

## 3. The 18 required scenarios

| # | Scenario | Backend test (`test_checker.py`) | Browser (`e2e_portal.mjs`) |
|---|---|---|---|
| 1 | Legitimate approved government URL → SAFE | `test_01` (synthetic approved registry entry) | — (no approved real entry exists) |
| 2 | Unknown website → WARNING, never SAFE | `test_02` | D3 (extension) |
| 3 | Suspicious bank login URL → FAKE | `test_03` | A1–A8 |
| 4 | Government impersonation URL → FAKE | `test_04` | — |
| 5 | Homograph domain (Cyrillic) → FAKE | `test_05` | — |
| 6 | Fake delivery-fee message → FAKE (with link) / WARNING (no link) | `test_06`, `test_06b` | A15–A18 |
| 7 | Fake government giveaway → FAKE (link) / MISLEADING (no link); Arabic fine and Arabic prize+OTP | `test_07`, `07b`, `07c`, `07d` | B5–B6 (Arabic) |
| 8 | Suspicious message containing a URL; OTP request without link | `test_08`, `test_08b` | A18 |
| 9 | Ordinary message (EN + AR) → WARNING, no signals, never SAFE | `test_09`, `test_09b` | — |
| 10 | Invalid input (5 cases) → 422, nothing stored | `test_10` ×5 | B2, B3 |
| 11 | Empty input (3 cases) → 422 | `test_11` ×3 | B1 |
| 12 | External/official source unavailable → SOURCE_UNAVAILABLE, partial, not SAFE; trust policy down → WARNING | `test_12`, `test_12b` | — |
| 13 | Backend failure → 503, nothing stored; storage failure → 503 with unsaved result | `test_13`, `test_13b` | B4 (backend unreachable → error, no verdict) |
| 14 | Database persistence of every field + redaction | `test_14` | A17 |
| 15 | Police Portal retrieval; private to the portal; not in feed/Guard | `test_15` | A8–A14 |
| 16 | Evidence traceable to the input | `test_16` | A4–A5, A13–A14 |
| 17 | Multiple findings: search, verdict/type/source/date filters, paging, facets | `test_17` | A11, A19 |
| 18 | Refresh / repeated requests do not duplicate | `test_18` | A20 (reload: 2 → 2), A21 |

Also: `test_checker_and_scan_agree_on_the_tag` (extension path = Checker path), request-id
validation and rate limiting (`test_request_id_and_rate_limit`).

Official-source scenarios use **synthetic** registry entries and records on `.example` domains
(`backend/tests/ws2/data/`), never real government data.

## 4. Browser acceptance test (35 checks, `ops/e2e_portal.mjs`)

**A — your acceptance workflow:** URL check → stored, verdict, normalised URL (tracking removed),
signals, expandable what/why/part, 3 checks, precautions, private to the portal → sign in → portal
lists it with the same verdict → search + type filter finds exactly it → finding page: same verdict
as Checker and database, same number of signals, authentication + verification + checks → message
check → stored as the next finding, message signals, phone number removed, link analysed → portal
lists it → **reload: both still there, no duplicates** → re-submitting the same message returns the
same finding.
**B** — empty input, unsupported link, server-side rejection, backend unreachable (no verdict),
Arabic UI analysing an Arabic message (RTL, Arabic labels), 375 px mobile (no horizontal overflow).
**C** — portal investigation → report → AI Analyst summary repeats the stored tag; no page errors.
**D** — the Chrome extension labels a Google results page with the backend's tag.

## 5. Not executed

| Not tested | Why |
|---|---|
| Real FastAPI runtime | not installable here (see §1) |
| Docker build / compose / HTTPS | no Docker daemon or network |
| Official-record retrieval (`registry fetch`) and live claim verification against real sites | no network; no approved entries in the shipped registry (approval is a step you run: `make setup-trust`) |
| Live Serper / DuckDuckGo / Google Places / crt.sh / feeds / Gemini / Groq / NextDNS | no network, no keys |
| Downloading the real Tranco list (`make reputation-update`) | no network here — tested with a fake downloader and a TEST ranking file; with no network the server correctly keeps nothing SAFE by reputation |
| Real RDAP servers, real page retrieval, real feeds for the Checker | no network — exercised with fakes; the live server showed the honest 'age unknown / not checked' path |
| Load testing, penetration test, dependency vulnerability scan | out of scope / offline |
| Safari, Firefox, real phones | not available (mobile tested via Chrome device emulation) |
| Removed WS3 demo-story gates (UI tour, offline, a11y on fixtures) | they tested demo fixtures that no longer exist; the acceptance test replaces them, but there is currently **no automated accessibility audit** |


## Guard (live) — smoke run, 2026-11-25

Real uvicorn, `GUARD_DOH_ENABLED=1`, fresh database, no NextDNS key, no internet:

| Call | Result |
|---|---|
| `GET /api/guard/stats` (fresh) | `blocklist_count 0`, `guard_mode doh`, `dot_hostname null` (not configured — no invented hostname), `honest_limits_key guard.limits_doh` |
| `GET /api/guard/blocklist.txt` | 200, `cache-control: public, max-age=60`, weak `etag`, header only |
| `POST /api/scan?guard=1` `https://adcb-secure-login.xyz/login` | FAKE / MALICIOUS 1.0, `guard.blocked false` (the extension scan never lists) |
| `POST /api/check` same URL | FAKE / MALICIOUS, `guard.blocked true`, `source checker`, `finding_id null` |
| `GET /api/guard/stats` | `blocklist_count 1`, `sync_health ok`, newest fake with source `checker` |
| `GET /api/guard/verdict?…&hit=1` | blocked, `counted true`; `GET /verdict?…` 200 text/html |
| `POST /api/guard/sync` ×2 | 200 `status ok`, then **429** `retry-after: 30` |
| DoH POST `www.adcb-secure-login.xyz` / GET `adcb-secure-login.xyz` | rcode 3 (NXDOMAIN), txid echoed |
| DoH POST `example.org` | rcode 2 (SERVFAIL): the upstream is unreachable from the sandbox — reported, not faked |
| server access log | 0 lines for `/dns-query` or `/verdict` |
| restart | list restored from SQLite |

**Not executed:** pushes to the real NextDNS API, NextDNS analytics, a real AdGuard Home, phones
using Private DNS, nginx verdict server. These are covered only by tests with mocked APIs.
