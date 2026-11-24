# Daggers — WS1 Runbook

## Cold start (judge laptop)

```bash
git status --short
make bootstrap
make clean           # optional: clear a partially seeded DB/assets after a failed older run
make seed
make demo
# second terminal
curl -s http://localhost:8000/api/status | python3 -m json.tool
curl -s http://localhost:8000/api/feed?limit=3 | python3 -m json.tool
curl -s http://localhost:8000/api/guard/feed
```

Expected: `mode=demo`, non-negative heartbeat ages, 6 findings, 4 evidence JPGs, and 3 malicious Guard rows.

`make bootstrap` prefers Python 3.11–3.14 and recreates `.venv`. On macOS Python 3.15, the pinned `Pillow==12.3.0` wheel avoids source-building against Homebrew FreeType. `make seed` uses the committed 60-entry gallery index and does not regenerate gallery JPGs.

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

## Integrated start order

1. Pull the integration branch, then run `make bootstrap` once. It recreates `.venv` with the pinned lightweight deps.
2. `make clean && make seed` — cold SQLite WAL, committed 60-entry gallery index, and four readable evidence JPGs.
3. `make check` — compile all three lanes and run the 199-check suite.
4. `make demo` — one FastAPI process on `:8000`: WS1 brain/API, WS2 sweep/Guard, and WS3 PWA/portal/AI.
5. Open `http://localhost:8000/?mode=demo#/feed` for the offline UI story and `http://localhost:8000/docs` for OpenAPI.
6. Verify the joins:

   ```bash
   curl -s http://localhost:8000/api/status
   curl -s 'http://localhost:8000/api/feed?limit=5'
   curl -s -X POST http://localhost:8000/api/sweep -H 'Content-Type: application/json' \
     -d '{"channel":"web"}'
   curl -s http://localhost:8000/api/guard/blocklist.txt
   curl -s http://localhost:8000/api/reports
   curl -s -X POST http://localhost:8000/api/report/7/analysis
   curl -s -o /dev/null -w '%{http_code}
' http://localhost:8000/
   curl -s -o /dev/null -w '%{http_code}
' http://localhost:8000/share
   ```

7. Full demo story: Checker → Finding/evidence → Portal report → AI summary/takedown → Sweep → Guard → Number, all from fixtures if the network is off.
8. Freeze: `make check`, `make snapshot`, and copy the snapshot to the second laptop/USB.


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
| macOS Python 3.15 + `Pillow` `libhvf.dylib` error | Pull the current branch, delete `.venv`, rerun `make bootstrap`; `Pillow==12.3.0` has a cp315 wheel. No manual FreeType/Homebrew fix is needed. |
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
