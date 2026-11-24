# Daggers — Three-lane integration

This branch integrates the three teammate branches into one FastAPI process while
preserving the technical spec's **one brain, every surface** rule.

## Source branches

| Branch | Lane | Imported as |
|---|---|---|
| `hafiz` | WS1 Brain & Evidence + bootstrap fix | base commit `d69f74b` |
| `mohammed` | WS2 Shield & Channels | `daggers-ws2-mohamed/**` flattened to repo root |
| `azhar` | WS3 Face & Analyst | `daggers/**` flattened to repo root |
| `main` | original first commit | not used as the integration target |

The integration work happens on `arena/2123c65d-daggers`. The final PR target is
`hafiz`, not `main`.

## What was flattened

WS2:

```text
backend/app/api/{sweep,guard}.py
backend/app/channels/**
backend/tests/ws2/**
guard/**
extension/**
docs/WS2.md · docs/RUNBOOK-WS2-section.md
```

WS3:

```text
web/**
backend/app/ai/**
backend/app/api/{ai,reports}.py
ops/**
docs/UI-KIT.md · docs/HANDOFF-WS3.md · docs/WS3.md
backend/tests/ws3/test_ai.py
```

## What was intentionally excluded

- WS3's standalone `backend/app/server.py` and `backend/app/store.py`.
- WS3's wrapper-shaped `backend/seed/fixtures/{feed,reports,status}.json`.
- Duplicate root `README.md`, `backend/requirements.txt`, and nested wrapper folders.
- WS3's standalone demo-server tests; WS1's FastAPI app is the only server.

WS1's frozen C1/C2/C4/C6 fixtures remain the deterministic source of truth. WS3's
`web/fixtures/**` remain the offline UI narrative and cache fallback.

## Shared integration seam

These WS1/shared files were adjusted so other lanes plug in without forking the brain:

- `backend/app/main.py` — mounts optional WS2/WS3 routers, serves `/`, `/share`,
  `/api/examples`, `/evidence`, and `/docs`.
- `backend/app/db/schema.sql` / `db/repo.py` — additive `sweep_results.detail`
  column plus `create_sweep_run`, `add_sweep_results`, `get_sweep_run`; all SQL
  stays in `repo.py`.
- `backend/app/db/repo.py` — `/api/guard/stats` keeps WS1 keys and adds WS3 aliases
  `blocked_today` and `feed_size`.
- `backend/app/api/reports.py` / `ai.py` — rewritten to read canonical report
  evidence from `request.app.state.runtime.repo` instead of WS3's demo store.
  AI outputs are stored in `meta`; AI never writes verdict/score/reasons.
- `web/js/api.js` — sends the exact WS1 `ScanRequest` shape (`kind`, `input`, `lang`)
  and passes active language to `/api/sweep`.
- `.env.example`, `Makefile`, `Dockerfile` — expose WS2 switches and template AI.
- `backend/tests/test_api_contracts.py` — old WS1-only scope audit replaced with
  an integrated-lane audit and HTTP smoke tests.

## Contract reconciliation

| Join | Resolution |
|---|---|
| WS3 `ScanResult.input_type` wording vs WS1 `kind` | WS1 §3 `kind` is authoritative; frontend now sends `kind`. |
| WS3 guard view `blocked_today` / `feed_size` | Added aliases without removing WS1 `blocked_domains` / `blocked_hits` / `mode`. |
| WS3 arbitrary sweep query pills | `SWEEP_ALLOW_ARBITRARY=1` in demo; WS2 still applies PII filters, length caps, rate limits, and fixture fallback. |
| WS2 sweep persistence | Uses WS1 SQLite tables through `repo.py`; in-memory fallback remains only if methods are absent. |
| WS3 report/AI routers | Use WS1 repository; no second store, no second verdict implementation. |
| PWA `share_target /share` | WS1 `main.py` serves `web/index.html`; `app.js` routes to `#/check`. |

## Smoke order

```bash
make bootstrap
make clean && make seed
make check
make demo
```

Then verify:

```bash
curl -s http://localhost:8000/api/status
curl -s http://localhost:8000/api/feed?limit=5
curl -s -X POST http://localhost:8000/api/sweep -H 'Content-Type: application/json' -d '{"channel":"web"}'
curl -s http://localhost:8000/api/guard/blocklist.txt
curl -s http://localhost:8000/api/reports
curl -s -X POST http://localhost:8000/api/report/7/analysis
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/share
open http://localhost:8000/docs
```

No API key, browser binary, Node build, or venue network is required for the
offline demo path.
