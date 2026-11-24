# Daggers — Brain & Evidence (Workstream 1)

> **We catch it, we prove it, we report it.** Daggers protects people from scam websites, messages, and numbers and files confirmed scams with evidence. This checkout implements **WS1: the deterministic brain, radar, evidence pipeline, SQLite store, exact API contracts, offline demo mode, and seed-on-boot**.

The other lanes can land later without renegotiating contracts: WS2 owns Guard/Sweep/Extension; WS3 owns the bilingual PWA, portal UI, and AI Analyst. `main.py` mounts their routers defensively when the modules exist, so this repository boots complete with only WS1 present.

---

## 30-second pitch

One brain powers every surface. A URL, pasted message, phone number, search result, Maps listing, or new certificate is normalized and scored by the **same pure Python core**. Every non-zero signal becomes a human-readable `reasons[]` line. Confirmed visual clones auto-create a **zero-PII police report**. AI may explain the evidence later; it never writes `verdict`, `score`, or `reasons`.

---

## Quickstart (<60 seconds cold)

Prerequisite: **Python 3.11+**. `make bootstrap` prefers `python3.11`–`python3.14` when available, deletes any stale `.venv`, and installs pinned wheels; Python 3.15 is also supported by the pinned `Pillow==12.3.0` wheel.

```bash
make bootstrap       # creates .venv and installs pinned lightweight deps
make seed            # SQLite WAL + committed 60-entry gallery index + 4 readable evidence JPGs
make demo            # DEMO_MODE=1, fully alive offline on :8000
```

If an older checkout created a Python 3.15 venv with `Pillow==11.0.0`, simply rerun `make bootstrap` after pulling; it recreates the venv. No manual `libhvf.dylib` or Homebrew FreeType fix is needed.

Then:

```bash
curl http://localhost:8000/api/status
curl http://localhost:8000/api/feed?limit=5
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"kind":"url","input":"https://adcb-secure-login.xyz/login","lang":"en"}'
open http://localhost:8000/docs
```

Use `make dev` for live tables with external pollers still disabled, `make test` for the brain/API suite, `make gallery` to regenerate the committed 60-shot perceptual-hash index, and `make check` for compile + tests.

No API key, browser binary, GPU, or venue network is required for the demo.

---

## Architecture

```text
PUBLIC ADAPTERS (opt-in)                BACKEND — one FastAPI process (:8000)
crt.sh · OpenPhish · URLhaus  ───────▶  radar/  crt · feeds · enrich · pipeline · cursors
RDAP · DNS · TLS · favicon    ───────▶          │
Playwright · pHash · ORB      ───────▶  vision/ │
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
                                      Guard JSONL feed         WS2/WS3 consumers
```

- **`core/` is pure**: no network, SQL, logging, or clock reads. All external facts arrive as `context`.
- **All SQL lives in `backend/app/db/repo.py`** and `schema.sql`.
- **Every external adapter has a fixture fallback and a timeout**.
- **Reports contain only fake-site artifacts**: domain, verdict, reasons, timestamps, evidence path, clone, gallery match. User input never enters a report.
- **Renderer safety**: 15-second timeout, read-only request guard, no downloads, no credentials, and no form submission. Disabled by default with `RENDER_ENABLED=0`.

See `docs/ARCHITECTURE.md`, `docs/API.md`, and `docs/RUNBOOK.md`.

---

## Frozen contracts

### `GET /api/feed?limit=50` → `[Finding]`, newest first

```json
{
  "id": 42,
  "domain": "adcb-secure-login.xyz",
  "verdict": "MALICIOUS",
  "score": 0.93,
  "reasons": ["brand typo/name 'adcb' (distance 0) outside adcb.ae"],
  "cert_issued": "2026-11-24T07:58:00Z",
  "first_seen": "2026-11-24T08:01:00Z",
  "source": "crt.sh",
  "clone": 97,
  "evidence_url": "/evidence/42.jpg",
  "gallery_match": "adcb.ae/login",
  "is_case_file": false
}
```

### `POST /api/scan` → `ScanResult`

```json
{
  "kind": "url",
  "input": "https://adcb-secure-login.xyz/login",
  "verdict": "MALICIOUS",
  "score": 0.95,
  "reasons": ["risky low-cost TLD .xyz", "brand typo/name 'adcb' (distance 0) outside adcb.ae"],
  "evidence_url": "/evidence/42.jpg",
  "scam_type": "fake-banking-login",
  "offline_capable": true
}
```

`kind` is `url | text | number`; `lang` is `en | ar`. URL/text/number checks are rules-only and therefore work offline. The echoed `input` is never persisted.

### Other WS1 endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/api/finding/{id}` | one `Finding` |
| GET | `/api/evidence/{id}.jpg` | readable side-by-side JPEG |
| GET | `/api/status` | `{mode, heartbeats, counts, uptime_s}` |
| GET | `/api/stream` | SSE `finding`, `sweep`, `heartbeat` |
| GET | `/api/guard/feed` | JSONL `GuardRow`, one line per domain |
| GET | `/api/guard/stats` | blocked domains / blocked hits |
| GET/POST | `/api/mode` | read or switch `live | demo` |
| GET | `/api/healthz` | Docker/health probe |

`GuardRow`:

```json
{"domain":"adcb-secure-login.xyz","verdict":"MALICIOUS","reason":"brand typo/name 'adcb' (distance 0) outside adcb.ae","flagged_at":"2026-11-24T08:01:00Z"}
```

`Report` (built by `reports/builder.py`, stored for WS3):

```json
{"id":7,"finding_id":42,"evidence":{ "…": "Finding object only" },"status":"SUBMITTED","auto":true,"filed_at":"2026-11-24T08:02:00Z","blocked_hits":1243}
```

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

The bundled catalog has **36 UAE brands** (banks, government, telecoms, airlines, delivery, marketplaces) with EN/AR aliases, plus EN/AR/Arabizi lure lexicons and a seeded list of **200 reported numbers**. `tldextract` is used through an offline snapshot resolver with a bundled static suffix fallback.

### The `аmazon.ae` class

Cyrillic `а` + Latin `mazon.ae` decodes from `xn--mazon-3ve.ae`, folds to `amazon.ae`, detects the mixed script, and receives both the punycode and homograph signals. A fully non-Latin legitimate domain such as `موقع.ae` stays clean unless it fold-spoofs a brand.

---

## Demo, live, and deployment

- `make demo` / `DEMO_MODE=1`: serves committed JSON fixtures, replays SSE findings, keeps every endpoint alive with no network.
- `make dev` / `MODE=live`: serves SQLite WAL; external pollers are still opt-in via `CRT_ENABLED`, `FEEDS_ENABLED`, `ENRICH_ENABLED`, and `RENDER_ENABLED`.
- `POST /api/mode` toggles the route at runtime.
- `/api/status` reports real monotonic heartbeat ages, honest counts, and `ai: "template"` until WS3 or `AI_STATE=ok` says otherwise.
- `Dockerfile` targets Hugging Face Spaces: Python 3.11, seed-on-boot, `RENDER_ENABLED=0` by default. Build with `--build-arg INSTALL_RENDER=1` for Playwright/Chromium/OpenCV.
- Cloudflare Pages origin goes in `CORS_ORIGINS`; `CORS_ORIGIN_REGEX` is available for a controlled `*.pages.dev` pattern.
- `.env.example` documents every switch. No secret is required for the offline path.

---

## Ownership boundaries

**WS1 owns:** `backend/app/main.py`, `config.py`, `core/**`, `radar/**`, `vision/**`, `db/**`, `reports/**`, `api/findings.py`, `api/scan.py`, `api/health.py`, `api/stream.py`, `backend/seed/**`, `backend/tests/**`, root build files, and WS1 docs.

**Defensively mounted if present:** `backend.app.api.sweep`, `.guard`, `.reports`, `.ai`. WS2/WS3 files are not touched by this lane. A static `web/` directory, if WS3 adds it, is mounted at `/`.

### Scope audit

No `web/**`, `guard/**`, `channels/**`, `extension/**`, `backend/app/ai/**`, `backend/app/api/sweep.py`, `backend/app/api/guard.py`, `backend/app/api/reports.py`, `backend/app/api/ai.py`, or `ops/demo/**` files were created. The technical spec explicitly assigns `docs/**` and the shared backend skeleton to WS1 at hour 0–2, so only `docs/ARCHITECTURE.md`, `docs/API.md`, and `docs/RUNBOOK.md` are included here. Small WS1 infrastructure files (`__init__.py`, `catalog.py`, `seed.py`, `.gitignore`, `.dockerignore`, and test fixtures) exist only to make the owned modules importable, seedable, testable, and free of generated artifacts in Git.

---

## Tests and quality bar

```bash
make test
# or: .venv/bin/python -m pytest backend/tests -q
```

The **93-check** suite covers scorer weights and thresholds, a 24-case golden accuracy matrix, claim-only `MISLEADING` capping, IDN/confusable homographs, official-domain allowlisting, EN/AR/Arabizi claims, offline number patterns, exact API schemas, JSONL Guard feed, configurable misleading-block policy, evidence JPEGs, seed-on-boot, SSE runtime, graceful enrichment-failure shape, zero-PII report validation, FreeType/font fallbacks, committed-gallery seed behavior, and a file-level WS2/WS3 scope audit.

Definition of Done verified here: `make seed && make demo` cold start; `/api/status`; C1/C2/C4/C6 shapes; `аmazon.ae`; 200-number seed; readable evidence JPG; zero-PII validation; seed-on-boot by deleting `backend/data`; Docker render-disabled fallback. `make test` suppresses a harmless Starlette/AnyIO deprecation warning from the installed test client; no application warnings or errors are emitted.

---

## Source context

This lane was built from the attached `daggers-the-plan.md` (what/why), `daggers-technical-spec.md` (whole-system context and ownership map), and `daggers-workstream-1-brain.md` (this lane's hard build brief). Those source documents are context and are intentionally not duplicated into this WS1 checkout. The WS1 shared-skeleton references are `docs/ARCHITECTURE.md`, `docs/API.md`, and `docs/RUNBOOK.md`.

*Daggers · SCAMSHIELD AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi.*
