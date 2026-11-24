# Daggers — WS1 Architecture

## Runtime shape

One Python 3.11 FastAPI process serves REST, SSE, static evidence, and runs four asyncio loops. SQLite WAL is the sole durable store. Heavy browser/vision work is optional and disabled in the default deployment.

```text
                         ┌──────────────────────────────────────────────┐
 PUBLIC ADAPTERS         │ BACKEND — uvicorn backend.app.main:app :8000   │  CONSUMERS
─────────────────        │                                              │ ─────────────────
 crt.sh / CT logs ──────▶│ radar/crt.py ─┐                              │  WS3 PWA / portal
 OpenPhish/URLhaus ─────▶│ radar/feeds.py├─▶ radar/pipeline.py           │  WS2 guard sync
 RDAP/DNS/TLS/ICON ─────▶│ radar/enrich.py┘        │                     │  extension / sweep
 Playwright + ORB ───────▶│ vision/**               │                     │  /docs OpenAPI
                         │                         ▼                     │
                         │              core/  ★ THE BRAIN               │
                         │  scorer · homograph · claims · numbers        │
                         │  verdicts · brands.yaml · lures.yaml          │
                         │                         │                     │
                         │       ┌─────────────────┼────────────────┐    │
                         │       ▼                 ▼                ▼    │
                         │ db/repo.py        reports/**          api/**   │
                         │ SQLite WAL        zero-PII C4         C1/C2/C6 │
                         │ seed-on-boot      autofile rule      SSE/REST  │
                         └──────────────────────────────────────────────┘
                                     │
                                     ▼
                         /evidence/{id}.jpg  ·  /api/guard/feed JSONL
```

## Boundaries

| Boundary | Rule |
|---|---|
| `core/**` | Pure functions only. No SQL, HTTP, file I/O, logging, or clock reads. External facts arrive through `context`. |
| `db/repo.py` | The only Python file containing SQL. `schema.sql` is the schema source. |
| `api/**` | Thin HTTP adapters. No verdict logic, no SQL. |
| `radar/**` | Every external call has `httpx`/`asyncio` timeouts and fixture fallback. |
| `vision/**` | Hard 15-second renderer timeout; no downloads, credentials, or form submission. Optional imports degrade to committed evidence JPGs. |
| `reports/**` | Recursive allowlist + forbidden-key/contact-value checks. No user input is accepted. |
| `main.py` | Owns `Runtime`, event bus, optional router mounting, and lifespan tasks. |

## Five flows

1. **Radar**: CT row → normalize → enrichment → triage → `core.scorer` → evidence JPG → finding → SSE → auto-file → Guard JSONL.
2. **Checker**: `POST /api/scan` → URL/text/number rules → exact `ScanResult`. No network call and no persistence of user input.
3. **Sweep**: WS2 adapters call the same brain. WS1 provides the `finding_id` and evidence contract; the sweep router is mounted when present.
4. **Report → AI**: WS1 builds a C4 evidence bundle from a C1 Finding. WS3 may stream an explanation; AI never writes the verdict.
5. **Guard**: `GET /api/guard/feed` emits one policy-filtered JSONL row per domain; WS2 syncs it to the resolver.

## Resilience

- `DEMO_MODE=1` serves committed fixtures and replays SSE findings without touching live tables.
- Startup seeds automatically when the DB file or `meta.seeded_at` is missing.
- crt.sh politeness: at most one query per `CRT_MIN_QUERY_GAP_S` (default 20s), custom `Daggers-Research/1.0` UA, and a 60-second poll loop.
- Every adapter failure returns an empty artifact instead of breaking a finding.
- `RENDER_ENABLED=0` is a first-class deployment mode; evidence comes from readable case-file JPGs.

## Security and privacy

- Reports carry only fake-site artifacts; `builder.py` rejects user-like keys and contact-like values recursively.
- `/api/scan` echoes input to the caller but never stores it.
- CORS is an explicit origin allowlist from `CORS_ORIGINS`; the optional regex is for controlled Pages deployments.
- The renderer aborts non-read requests, disables downloads, and never fills or submits forms.
