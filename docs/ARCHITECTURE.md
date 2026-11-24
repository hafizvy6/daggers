# Daggers — Architecture

## Runtime shape

One Python 3.11+ FastAPI process serves REST, SSE, the static `web/` PWA, static evidence, and runs the (opt-in) asyncio loops. SQLite WAL is the sole durable store; sweep runs persist through `db/repo.py`. Heavy browser/vision work is optional and disabled by default.

```text
                         ┌──────────────────────────────────────────────┐
 PUBLIC ADAPTERS         │ BACKEND — uvicorn backend.app.main:app :8000   │  CONSUMERS
─────────────────        │                                              │ ─────────────────
 crt.sh / CT logs ──────▶│ radar/crt.py ─┐          (CRT_ENABLED=1)     │  PWA / portal
 OpenPhish/URLhaus ─────▶│ radar/feeds.py├─▶ radar/pipeline.py           │  extension/
 RDAP/DNS/TLS/favicon    │ radar/enrich.py┘        │  (ENRICH_ENABLED)   │  guard/ sync
 Serper/DuckDuckGo       │ channels/search.py      │  (SEARCH_LIVE_ENABLED)             │
 Google Places           │ channels/maps.py        │  (MAPS_LIVE_ENABLED)│             │
 Playwright + pHash ────▶│ vision/**               │  (RENDER_ENABLED)   │  /docs OpenAPI
                         │                         ▼                     │
                         │              core/  ★ THE BRAIN               │
                         │  scorer · homograph · claims · numbers        │
                         │  verdicts · brands.yaml · lures.yaml          │
                         │                         │                     │
                         │       ┌─────────────────┼────────────────┐    │
                         │       ▼                 ▼                ▼    │
                         │ db/repo.py        reports/**          api/**   │
                         │ SQLite WAL        zero-PII C4         C1/C2/C6 │
                         │ empty-on-boot   auto-dossier rule    SSE/REST  │
                         └──────────────────────────────────────────────┘
                                     │
                                     ▼
                         /evidence/{id}.jpg  ·  /api/guard/feed JSONL
```

## Boundaries

| Boundary | Rule |
|---|---|
| `core/**` | Pure functions only. No SQL, HTTP, file I/O, logging, or clock reads. External facts arrive through `context`. |
| `db/repo.py` | The only Python file containing SQL. `schema.sql` is the schema source. Boot initializes an empty schema; no rows are inserted. |
| `api/**` | Thin HTTP adapters. No verdict logic, no SQL. |
| `radar/**` | Every external call has `httpx`/`asyncio` timeouts. When disabled/unconfigured the loop exits immediately and reports an honest heartbeat; nothing fabricates a finding. |
| `vision/**` | Hard 15-second renderer timeout; no downloads, credentials, or form submission. Optional imports degrade to "no evidence available" (never an invented image). |
| `reports/**` | Recursive allowlist + forbidden-key/contact-value checks. No user input is accepted. |
| `main.py` | Owns `Runtime`, event bus, optional router mounting, and lifespan tasks. |

## Five flows

1. **Radar**: CT row → normalize → enrichment → triage → `core.scorer` → *(optional) real evidence JPG* → finding → SSE → automatic portal dossier → Guard JSONL. Disabled by default; enable per adapter flag.
2. **Checker**: `POST /api/scan` → URL/text/number rules → exact `ScanResult`. No network call; the input is echoed, never persisted.
3. **Sweep**: `POST /api/sweep` with a canonical `query_id` (or a free-text query when `SWEEP_ALLOW_ARBITRARY=1`) → Search/Maps adapter → same brain → rows persisted, `source_kind` honestly `live` or `unconfigured`.
4. **Report → AI**: `reports/builder.py` builds the C4 evidence bundle from a C1 Finding. `api/ai.py` streams an explanation built solely from that bundle; AI never writes `verdict`, `score`, or `reasons`.
5. **Guard**: `GET /api/guard/feed` emits one policy-filtered JSONL row per confirmed fake; `guard/sync_nextdns.py` pushes them to NextDNS when an operator runs it with a key and profile.

## Resilience without fabrication

- Every adapter is opt-in. With zero flags set, the app is a healthy, quiet system: empty feed, zero counts, SSE heartbeats, full OpenAPI — and nothing invented.
- crt.sh politeness: at most one query per `CRT_MIN_QUERY_GAP_S` (default 20s), custom `Daggers-Research/1.0` UA, and a poll loop.
- Every adapter failure returns an empty artifact instead of breaking a finding; findings are never synthesized to fill a gap.
- `RENDER_ENABLED=0` keeps evidence absent rather than simulated. `RENDER_ENABLED=1` requires `make install-render` and still produces only real captures.
- Sweep free-text is refused unless `SWEEP_ALLOW_ARBITRARY=1`, preventing the endpoint from becoming an open proxy.

## Security and privacy

- Reports carry only fake-site artifacts; `builder.py` rejects user-like keys and contact-like values recursively.
- `/api/scan` echoes input to the caller but never stores it.
- CORS is an explicit origin allowlist from `CORS_ORIGINS`; the optional regex is for controlled Pages deployments.
- The renderer aborts non-read requests, disables downloads, and never fills or submits forms.
- Provider keys are server-side only (`GEMINI_KEY`, `GROQ_KEY`, `SERPER_API_KEY`, `GOOGLE_PLACES_API_KEY`, `PHISHTANK_KEY`, `NEXTDNS_API_KEY`). The browser, the PWA bundle, and the MV3 extension never receive them; `/api/healthz` reports booleans only.

## Module map

| Path | Role | Joins to the brain by |
|---|---|---|
| `core/**` | Deterministic scorer, homograph/claim/number rules, brand/lure catalogs | pure functions, `context` dicts |
| `radar/**` | crt.sh poller, phishing feeds, enrichment, pipeline, cursors | emits `Finding` via `db/repo.py`, publishes SSE |
| `vision/**` | optional Playwright render, pHash/ORB compare, evidence composer, gallery index loader | `RENDER_ENABLED`, operator-supplied gallery |
| `channels/**` | sweep engine, Search/Maps adapters, official-registry verification | in-process `core.scorer`, persisted via `repo.py` |
| `channels/official/**` | human-approved registry of official domains (CLI: approve/revoke/verify/fetch) | feeds S2 identity checks when approved |
| `db/**` | SQLite schema + repository; the only SQL | `schema.sql` |
| `reports/**` | C4 builder (zero-PII), queue, automatic dossier policy | `finding_id` → evidence bundle |
| `ai/**` | provider chain (Gemini → Groq → template), prompt builder, evidence-only filter | `Report.evidence` in, text out |
| `api/**` | health, findings, scan, stream, sweep, guard, reports, AI, examples | thin HTTP adapters |
| `web/**` | bilingual (EN/AR, RTL) PWA, service worker, i18n catalogs | fetches/SSE against same origin |
| `extension/**` | MV3: pins action title to `/api/scan` verdict | same-origin or configured API base |
| `guard/**` | NextDNS sync script for operators | reads `/api/guard/feed`, pushes via NextDNS API |
| `ops/**` | `check_syntax.mjs`, `check_i18n.py`, `verify_empty.py` gates and tooling | CI/pre-flight |

There is one app, one store, and one verdict implementation — historical lane boundaries (WS1/WS2/WS3) are gone; the tree is a single integrated codebase.
