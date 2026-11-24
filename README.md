# Daggers — We catch it, we prove it, we report it.

Daggers protects people from scam websites, messages, and phone numbers — and files confirmed scams with zero-PII evidence. One deterministic Python brain scores every surface (URL, pasted message, number, search result, Maps listing, new certificate), the same engine behind the bilingual PWA, the Guard DNS blocklist, the Chrome extension, and the police-report portal.

There is **no demo mode and no seed data**. A cold start against an empty database is a valid, honest state: the radar shows "watching — nothing observed yet", and every adapter stays disabled until you explicitly enable and configure it. Nothing is fabricated, replayed, or re-seeded behind your back.

---

## Quickstart

Prerequisite: **Python 3.11+** and, for the full test suite, Node 18+.

```bash
make bootstrap       # create .venv and install pinned wheels
cp .env.example .env # optional — every default is safe and disabled
make dev             # live app on :8000 (SQLite at backend/data/daggers.db)
```

Then:

```bash
curl http://localhost:8000/api/healthz          # adapter readiness, no secrets
curl http://localhost:8000/api/status           # honest zero counts on a cold start
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"kind":"url","input":"https://adcb-secure-login.xyz/login","lang":"en"}'
open http://localhost:8000/docs                 # OpenAPI
```

The app serves the bilingual PWA at `http://localhost:8000/`. `/api/mode` always returns `live`. See **[docs/RUNBOOK.md](docs/RUNBOOK.md)** for the full operator guide — enabling live adapters, API keys, Docker, Cloudflare Pages, Hugging Face Spaces, NextDNS, the extension, and the official-registry approval flow.

No key, browser, GPU, or network is required to *boot*. External data only flows when you turn an adapter on.

---

## Architecture

```text
PUBLIC ADAPTERS (opt-in, all default off)     BACKEND — one FastAPI process (:8000)
crt.sh · OpenPhish · URLhaus · PhishTank ───▶  radar/   crt · feeds · enrich · pipeline
RDAP · DNS · TLS · favicon           ───────▶          │
DuckDuckGo / Serper · Google Places  ───────▶  channels/  sweep · search · maps
Playwright · pHash (optional)        ───────▶  vision/    │
                                                        ▼
                         core/  ★ THE BRAIN — pure functions, zero I/O
                         normalize · lexical · identity/homograph · claims
                         numbers · weighted score · verdict · reasons[]
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         ▼                     ▼                     ▼
                      db/ SQLite WAL      reports/ C4 bundles      api/ REST + SSE
                      all SQL in repo.py  zero-PII allowlist       exact C1/C2/C6
                                               │                     │
                                               ▼                     ▼
                                      Guard JSONL feed        web/ PWA · extension/
```

- **`core/` is pure**: no network, SQL, logging, or clock reads. All external facts arrive as `context`.
- **All SQL lives in `backend/app/db/repo.py`** and `schema.sql`. Tables start empty.
- **Every external adapter is off by default and opt-in** (`CRT_ENABLED`, `FEEDS_ENABLED`, `ENRICH_ENABLED`, `RENDER_ENABLED`, `SEARCH_LIVE_ENABLED`, `MAPS_LIVE_ENABLED`). Disabled adapters return honest "unconfigured/empty" states.
- **Reports contain only fake-site artifacts**: domain, verdict, reasons, timestamps, evidence path, clone, gallery match. User input never enters a report.
- **Renderer safety**: 15-second timeout, read-only request guard, no downloads, no credentials, no form submission. Requires `RENDER_ENABLED=1` and the optional Playwright stack (`make install-render`).
- **Evidence is real or absent**: a finding's evidence JPG exists only if a live renderer captured one. Nothing generates stand-in imagery.
- **AI never writes `verdict`, `score`, or `reasons`**. It explains evidence after the fact, and streams `template` output until `AI_STATE=live` plus a provider key is configured.

See `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/RUNBOOK.md`, and `docs/UI-KIT.md`.

---

## Frozen contracts

### `GET /api/feed?limit=50` → `[Finding]`, newest first

```json
{
  "id": 1,
  "domain": "example-scam.example",
  "verdict": "MALICIOUS",
  "score": 0.93,
  "reasons": ["brand typo/name 'adcb' (distance 0) outside adcb.ae"],
  "cert_issued": "2026-11-24T07:58:00Z",
  "first_seen": "2026-11-24T08:01:00Z",
  "source": "crt.sh",
  "clone": 97,
  "evidence_url": "/evidence/1.jpg",
  "gallery_match": "adcb.ae/login",
  "is_case_file": false
}
```

An empty database returns `[]` — not a sample.

### `POST /api/scan` → `ScanResult`

```json
{
  "kind": "url",
  "input": "https://adcb-secure-login.xyz/login",
  "verdict": "MALICIOUS",
  "score": 0.95,
  "reasons": ["risky low-cost TLD .xyz", "brand typo/name 'adcb' (distance 0) outside adcb.ae"],
  "evidence_url": null,
  "scam_type": "fake-banking-login",
  "offline_capable": true
}
```

`kind` is `url | text | number`; `lang` is `en | ar`. URL/text/number checks are rules-only and need no network. The echoed `input` is never persisted. `evidence_url` is only present when a live renderer stored a real capture.

### Other endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/api/finding/{id}` | one `Finding`, or 404 |
| GET | `/api/evidence/{id}.jpg` (alias `/evidence/{id}.jpg`) | real captured side-by-side JPEG, or 404 |
| GET | `/api/status` | `{mode, heartbeats, counts, uptime_s}` |
| GET | `/api/healthz` | adapter readiness (`ok`, `mode`, `adapters{}`) |
| GET | `/api/stream` | SSE `finding`, `sweep`, `heartbeat` |
| GET | `/api/mode` | `{"mode":"live"}` |
| GET | `/api/guard/feed` | JSONL `GuardRow` (empty until real confirmed fakes exist) |
| GET | `/api/guard/stats` | blocked domains / blocked hits |
| GET | `/api/guard/config` | DNS hostname for Private DNS, or `configured:false` |
| GET | `/api/guard/blocklist.txt` | 0.0.0.0-prefixed host list for the sync script |
| GET | `/api/examples` | canonical sweep query presets (no sample findings/numbers) |
| POST | `/api/sweep` | run a canonical/allowed query; empty `results` when unconfigured |
| POST | `/api/reports` | build/file a zero-PII report from a real finding id |
| POST | `/api/report/{id}/analysis`, `/api/report/{id}/takedown` | streamed AI explainer / deterministic template |

`GuardRow`: `{"domain":"...","verdict":"MALICIOUS","reason":"...","flagged_at":"..."}`

`Report`: `{"id":7,"finding_id":1,"evidence":{ "…": "Finding object only" },"status":"SUBMITTED","auto":true,"filed_at":"...","blocked_hits":0}`

The four UI tags map as `UNKNOWN → SAFE`, `SUSPICIOUS → WARNING`, `MISLEADING → MISLEADING`, `MALICIOUS → FAKE`.

---

## The deterministic brain

Pipeline: **S0 normalize → S1 lexical → S2 identity → S3 claims → S4 vision context → S5 infra context → S6 verdict**.

| Signal | Weight |
|---|---:|
| Brand exact/typo distance ≤1 on non-official host | +0.55 |
| Brand typo distance 2 | +0.35 |
| Brand token anywhere in non-official URL | +0.25 |
| Mixed-script IDN or confusable brand spoof | +0.45 |
| Giveaway/amount + entity claim + non-official host | +0.50, floors verdict at `MISLEADING` |
| Punycode `xn--` | +0.35 |
| IP-literal host / `@` authority | +0.40 / +0.30 |
| Risky TLD / lure keyword / path depth / gibberish | +0.15 / +0.20 / +0.10 / +0.15 |
| TLS certificate age <24h | +0.25 |
| Confirmed phishing feed | +0.70 |
| Visual clone ≥90% with brand hit | +0.60 |
| Foreign form action / payment fields / obfuscated script | +0.30 / +0.25 / +0.15 |

`score = clamp(sum, 0, 1)`; `MALICIOUS ≥ 0.65`, `SUSPICIOUS ≥ 0.35`, otherwise `UNKNOWN`. A claim floors the verdict at `MISLEADING`; claim-only cases are also capped at `MISLEADING` so unrelated lexical weight cannot turn an unverifiable claim into a confirmed FAKE. A clone match, confirmed feed label, foreign form action, or payment-harvest fields remove that cap. Auto-file requires `MALICIOUS ∧ clone ≥ 90`; Guard blocks `MALICIOUS` by default, with `GUARD_BLOCK_MISLEADING=1` as a policy flag.

The bundled catalog has **36 UAE brands** (banks, government, telecoms, airlines, delivery, marketplaces) with EN/AR aliases, plus EN/AR/Arabizi lure lexicons. The reported-number catalog contains 200 deterministic premium/VoIP/repeat-pattern signatures — they are rules, not stored victim data. `tldextract` runs against an offline snapshot resolver with a bundled static suffix fallback.

### The `аmazon.ae` class

Cyrillic `а` + Latin `mazon.ae` decodes from `xn--mazon-3ve.ae`, folds to `amazon.ae`, detects the mixed script, and receives both the punycode and homograph signals. A fully non-Latin legitimate domain such as `موقع.ae` stays clean unless it fold-spoofs a brand.

---

## Bring it to life

A bare boot is honest but quiet. To see real findings:

1. Set `CRT_ENABLED=1` and start the app — the crt.sh poller watches new UAE-brand certificates. Keep `HTTP_USER_AGENT` identifiable.
2. Set `FEEDS_ENABLED=1` (optionally `PHISHTANK_KEY=…`) — the OpenPhish/URLhaus poller labels confirmed scams.
3. Set `ENRICH_ENABLED=1` — RDAP age, DNS, TLS issuer/age and favicon hash join findings.
4. Install the renderer (`make install-render`), set `RENDER_ENABLED=1` — Playwright captures pages, pHash/ORB compare against the operator-supplied gallery index, and **real evidence JPGs** are composed and stored.
5. Operators seed their own perceptual-hash reference set with `backend/app/vision/gallery.py`; the repository ships no gallery images.
6. Enable the Sweep provider (`SEARCH_LIVE_ENABLED=1`, optional `SERPER_API_KEY`; or `MAPS_LIVE_ENABLED=1` + `GOOGLE_PLACES_API_KEY`) and approve official sources through `backend.app.channels.official.cli`.
7. For AI explanations, set `AI_STATE=live` with `GEMINI_KEY` and/or `GROQ_KEY`. Without them the deterministic template is used and clearly labeled as such.
8. Point `guard/sync_nextdns.py` (on an operator machine, never in the browser) at the API to push the confirmed-fake blocklist to NextDNS.

**[docs/RUNBOOK.md](docs/RUNBOOK.md) is the setup guide** — `.env` reference, key acquisition, deployment (Docker, Cloudflare Pages + HF Space, CORS), PWA install, extension loading, sync verification, and troubleshooting for blocked registries and unconfigured states.

---

## Repository layout

`backend/app/{core,radar,vision,db,reports,ai,channels,api}` · `backend/tests/**` (test doubles live only here) · `web/` (bilingual PWA, service worker) · `extension/` (MV3, pins action title to API verdict) · `guard/` (NextDNS sync) · `ops/` (i18n/syntax gates, empty-boot verifier) · `docs/`.

## Tests and quality bar

```bash
make check   # compile + i18n/design gate + node syntax + extension unit tests + pytest
make verify-empty  # boots a fresh install against a temp DB and proves zero product data
```

*Daggers · SCAMSHIELD AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi.*
