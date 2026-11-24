<!-- WS2 section appended to the end of docs/RUNBOOK.md in the full repository. Included separately here because RUNBOOK.md is a WS1-owned file. -->

## WS2

Full reference: `docs/WS2.md`. WS2 routers mount automatically through WS1's optional-router loader.

### Smoke checks

| Check | Command | Expected |
|---|---|---|
| Sweep (web) | `curl -s -X POST :8000/api/sweep -H 'Content-Type: application/json' -d '{"channel":"web"}'` | run with `source_kind`, `counts`, `results[].tag` |
| Sweep (maps) | same with `{"channel":"maps"}` | rows with `maps.checks.identity/website/phone` |
| Sweep fetch | `curl -s :8000/api/sweep/1` | same run; 404 for unknown id |
| Arbitrary query | `-d '{"channel":"web","query":"x y z"}'` | 403 unless `SWEEP_ALLOW_ARBITRARY=1` |
| Blocklist | `curl -s :8000/api/guard/blocklist.txt` | `0.0.0.0 <domain>` lines, MALICIOUS only |
| Guard sync | `curl -s :8000/api/guard/sync-status` | `status: ok`, `block_events_measured: false` |
| Registry | `python -m backend.app.channels.official.cli validate` | `OK` |
| WS2 tests | `python -m pytest -q --confcutdir=backend/tests/ws2 backend/tests/ws2` | all pass (API tests need fastapi+httpx) |
| Extension tests | `node --test extension/tests/core.test.js` | 9 pass |

### Demo truths to state out loud

* Search/Maps results in demo mode are **SYNTHETIC fixtures** (`source_kind: fixture`).
* Every official registry entry is **pending** until a named reviewer approves it, so no site shows SAFE yet.
* `/api/scan` applies the never-SAFE-for-unknown policy only after WS1 merges `patches/ws1/0001` + `0002`.
* NextDNS block events are **not measured** by Daggers.

### WS2 incident fallbacks

| Failure | Action |
|---|---|
| Serper/DDG/Places down or rate-limited | Leave `SEARCH_LIVE_ENABLED=0` / `MAPS_LIVE_ENABLED=0`; fixtures answer, labelled synthetic. |
| Sweep returns 429/503 | Wait 60 s or lower demo traffic; limits are `SWEEP_RATE_PER_MIN` / `SWEEP_MAX_CONCURRENT`. |
| Registry file invalid after an edit | `cli validate`; the app keeps the old file because the CLI writes atomically after validation. |
| Guard feed error | `sync-status` shows `stale`; the last good blocklist keeps being served. |
| Extension shows NOT CHECKED everywhere | Backend unreachable: check the popup's backend URL and `/api/healthz`. |
| Need to approve a source live on stage | `cli approve <id> --reviewer "Name"` only if the reviewer has really verified it. |
