# Daggers — Workstream 2: Shield & Channels

> **Integrated build note:** the WS1 patches described below have been applied in this repository and the `patches/` folder removed. See `docs/INTEGRATION-REPORT.md`.


> **Daggers protects people from scam websites.** WS2 is the part that reaches users: it labels
> search results, sweeps Google Search and Maps for scams, checks government claims against official
> UAE sources, and turns confirmed scams into a DNS blocklist.

*Unofficial hackathon prototype (SCAMSHIELD AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi).
Not an official UAE Police or government product.*

---

## What WS2 adds

| Feature | What it does | Where |
|---|---|---|
| **Trust policy** | Turns evidence into one label: `SAFE` · `WARNING` · `MISLEADING` · `FAKE` | `backend/app/channels/trust_policy.py` |
| **Official UAE source registry** | Human-approved list of real government domains (Class A authorities, Class B official media, Class C independent media) | `backend/app/channels/official/` |
| **Government claim checker** | Checks claims like "ICP announces visa amnesty" against approved official records, in Arabic and English | `backend/app/channels/official/verify.py` |
| **Secure source fetcher** | Downloads only approved official pages/feeds, safely | `backend/app/channels/official/fetch.py` |
| **Search channel** | Scores web search results (Serper → DuckDuckGo → offline fixtures) | `backend/app/channels/search.py` |
| **Maps channel** | Checks map listings: identity, website, and phone, each separately | `backend/app/channels/maps.py` |
| **Sweep API** | `POST /api/sweep`, `GET /api/sweep/{id}` | `backend/app/api/sweep.py` |
| **Guard** | `GET /api/guard/blocklist.txt`, `GET /api/guard/sync-status`, NextDNS push script | `backend/app/api/guard.py`, `guard/` |
| **Chrome extension** | Labels Google search results in the browser | `extension/` |
| **WS1 integration patches** | Proposed changes to WS1 code (not applied) | `patches/ws1/` |

---

## The labelling rule

**SAFE is earned, never assumed.** A site is SAFE only if its exact domain is an **approved, current
official source** *and* nothing suspicious is found.

| Situation | Label |
|---|---|
| Approved official domain, nothing suspicious | **SAFE** |
| Unknown, pending, revoked, expired, or uncheckable domain | **WARNING** |
| Government claim contradicted by official evidence | **MISLEADING** |
| Government claim checked against official sources and not confirmed | **MISLEADING** |
| Official sources unavailable, out of date, or disagreeing | **WARNING** (manual review) |
| Confirmed phishing, impersonation, or fraud | **FAKE** |
| Suspicious content on a genuine official domain (e.g. a forum post) | **WARNING** (manual review), never FAKE |

Domain authenticity and claim truth are checked **separately**, and every result reports both,
plus WS1's scam evidence and the final label.

---

## Quick start

```bash
make bootstrap        # install WS1's dependencies (WS2 needs nothing extra)
make dev              # backend on http://localhost:8000 (live only)
```

Try it:

```bash
curl -s -X POST localhost:8000/api/sweep -H 'Content-Type: application/json' -d '{"channel":"web"}'
curl -s -X POST localhost:8000/api/sweep -H 'Content-Type: application/json' -d '{"channel":"maps"}'
curl -s localhost:8000/api/sweep/1
curl -s localhost:8000/api/guard/blocklist.txt
curl -s localhost:8000/api/guard/sync-status
```

Chrome extension: `chrome://extensions` → **Developer mode** → **Load unpacked** → choose `extension/`,
then search on google.com or google.ae.

Optional live services (off by default; see `backend/app/channels/ws2.env.example`):
`SEARCH_LIVE_ENABLED`, `SERPER_API_KEY`, `MAPS_LIVE_ENABLED`, `GOOGLE_PLACES_API_KEY`,
`SWEEP_ALLOW_ARBITRARY`.

---

## Approving official sources

Every seeded registry entry starts as **pending** — so nothing is SAFE until a person approves it.

```bash
python -m backend.app.channels.official.cli list --status pending
python -m backend.app.channels.official.cli show wam
python -m backend.app.channels.official.cli approve wam --reviewer "Your Name"
python -m backend.app.channels.official.cli revoke wam --reviewer "Your Name" --reason "why"
python -m backend.app.channels.official.cli validate
```

Approve an entry only after checking its domains against the organization's own official channels.
Restart the backend afterwards.

---

## Tests

```bash
python -m pytest -q --confcutdir=backend/tests/ws2 backend/tests/ws2
node --test extension/tests/core.test.js
```

| Suite | Result in the build environment |
|---|---|
| WS2 Python tests (14 required scenarios + policy invariants, registry, fetcher, channels, sweep, guard) | **90 passed**, 0 failed |
| WS2 API tests (real HTTP) | 3 skipped: FastAPI/httpx not installable there; run them with `make bootstrap` |
| Chrome extension (Node) | **9 passed**, 0 failed |
| WS1 offline tests, before and after WS2 (and with the patches applied) | **73 passed**, unchanged |

All test data is synthetic: fabricated `.example` domains, kept under `backend/tests/ws2/data/` and never reachable from the running app.
No real government evidence was invented.

---

## Status

**Done and tested:** trust policy, registry + CLI, claim checker (Arabic/English), evidence and
snapshots, secure fetcher (with simulated network), directory discovery (with a synthetic page),
Search, Maps, Sweep, Guard, Chrome extension.

**Waiting on WS1** (`patches/ws1/`, apply with `patch -p1 < file`):

| Patch | Effect |
|---|---|
| `0001`, `0002` | `/api/scan` stops labelling unknown sites SAFE. **Until then, the main scan API still does.** |
| `0003` | Claim warning no longer says "not found on official channels" when nothing was checked |
| `0004` | Sweep results saved to SQLite (currently in memory only, lost on restart) |
| `0005` | Updates WS1 tests: 2 break as soon as WS2 files exist, 3 more if 0001/0003 are merged |

**Waiting on WS3:** use the `tag` field, show `domain_auth` and `gov_verification`. Data formats are in
`docs/WS2.md` §4, §7, §8, §11.

**Not yet run against live services:** official-source fetching, Serper, DuckDuckGo, Google Places,
the U.AE directory page, NextDNS, and the extension in a real browser. The extension is not on the
Chrome Web Store.

**Not done:** no registry entry is approved yet; AI/semantic claim matching (optional) is not built.

---

## Ownership

WS2 did **not** modify any WS1 code. Changes WS1 needs are delivered as patches only. The one edit to
an existing file is a `## WS2` section appended to `docs/RUNBOOK.md`.

## More detail

* `docs/WS2.md` — full technical reference (contracts, security review, limitations)
* `extension/README.md` — extension install, behaviour, privacy
* `guard/README.md` — blocklist and NextDNS
* `docs/RUNBOOK.md` — live operations, acceptance check and troubleshooting
