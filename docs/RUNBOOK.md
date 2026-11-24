# Daggers — WS1 Runbook

## Cold start (judge laptop)

```bash
git status --short
make bootstrap
make seed
make demo
# second terminal
curl -s http://localhost:8000/api/status | python3 -m json.tool
curl -s http://localhost:8000/api/feed?limit=3 | python3 -m json.tool
curl -s http://localhost:8000/api/guard/feed
```

Expected: `mode=demo`, non-negative heartbeat ages, 6 findings, 4 evidence JPGs, and 3 malicious Guard rows.

For live SQLite tables with external adapters still off:

```bash
make dev
```

To prove seed-on-boot:

```bash
make clean
python3 -m backend.seed.seed --seed-only   # or simply start the app; it seeds automatically
```

## Health checks

| Check | Command | Expected |
|---|---|---|
| Process | `GET /api/healthz` | `{"ok":true,...}` |
| Brain/status | `GET /api/status` | real heartbeat ages, counts, honest `ai` |
| Feed | `GET /api/feed?limit=5` | C1 rows |
| Detail | `GET /api/finding/42` | C1 object |
| Evidence | `GET /api/evidence/42.jpg` | JPEG, projector-readable |
| Checker | `POST /api/scan` | C2 object, `offline_capable:true` |
| Number | `POST /api/scan {"kind":"number","input":"+971900000001"}` | `MALICIOUS` |
| Guard | `GET /api/guard/feed` | JSONL malicious rows |
| Stream | `curl -N http://localhost:8000/api/stream` | heartbeat + finding events |
| Tests | `make test` | all green |

## Start order for all three lanes

1. WS1: `make seed && make demo` and verify `/api/status`.
2. WS2: confirm `/api/guard/feed`, then point Guard sync and extension API base at this origin.
3. WS3: set `CORS_ORIGINS` to the exact Pages origin, mount `web/`, then exercise `/api/scan`, `/api/feed`, and optional report/AI routes.
4. Full smoke: scan → finding → evidence → report → AI → portal, all from fixtures.
5. Freeze: `make check`, `make snapshot`, and copy the snapshot to the second laptop/USB.

## External adapter switches

All off by default for venue reliability:

- `CRT_ENABLED=1` — crt.sh CT poller, one query per ≥20 seconds.
- `FEEDS_ENABLED=1` — OpenPhish + URLhaus text feeds.
- `ENRICH_ENABLED=1` — RDAP, DNS, TLS, and favicon hash, each timeout-isolated.
- `RENDER_ENABLED=1` — Playwright + ORB; requires `make install-render`.
- `DEMO_MODE=1` — fixtures win; live pollers are not called.

Custom UA is `Daggers-Research/1.0`. Every adapter uses a timeout and returns an empty artifact on failure.

## Demo ladder

1. Public HF Space URL + Cloudflare Pages origin.
2. Same laptop: `make dev`.
3. Offline snapshot: `make demo` with network disabled.

`POST /api/mode {"mode":"demo"}` switches at runtime. `POST /api/mode {"mode":"live"}` switches back to SQLite.

## Incident fallbacks

| Failure | Action |
|---|---|
| Venue network down | `make demo`; all REST/SSE/evidence/report shapes survive from fixtures. |
| Playwright/Chromium missing | Leave `RENDER_ENABLED=0`; committed side-by-side JPEGs are served. |
| HF Space disk reset | Startup detects missing DB and runs seed-on-boot. |
| AI provider/key unavailable | `AI_STATE=template`; WS3 uses the same structured summary shape. |
| crt.sh rate-limit or outage | `CRT_ENABLED=0`; replay fixture findings through SSE. |
| CORS blocked on Pages | Set `CORS_ORIGINS` to the exact `https://...pages.dev` origin or a narrow `CORS_ORIGIN_REGEX`. |
| Evidence directory cleared | Restart or `make seed`; case-file JPGs are copied back. |

## Safety reminders

- Never paste real victim messages into a report or commit them to a fixture.
- The Checker response may echo user input; the backend never stores it.
- AI may explain evidence but never sets `verdict`, `score`, or `reasons`.
- The renderer never submits a form; non-read requests are aborted.
- Reports contain the crime, not the victim.
