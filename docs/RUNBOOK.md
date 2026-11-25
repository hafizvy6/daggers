# Daggers — Operations runbook (live)

Daggers has **one mode: live**. There is no demo mode, no seed data and no fixture
fallback. A fresh install is empty: the radar feed is empty until real adapters are
enabled, and the Police Portal fills up as people use the Checker and investigators
open investigations.

## Start

```bash
make bootstrap                          # .venv + pinned dependencies (keeps an existing .venv)
make bootstrap PIP_INDEX=https://pypi.org/simple   # if pip.conf points at a private mirror
make dev                                # http://localhost:8000 — this computer opens the portal without login
make user U=admin R=admin               # only for other computers / production (password prompted)
```

## Health checks

```bash
curl -s localhost:8000/api/healthz      # {"ok":true, "database":"ok", "adapters":{…}} — 503 if the DB is down
curl -s localhost:8000/api/status       # live counts and heartbeats
```

`adapters` shows, as booleans only, which external sources are enabled/configured
(crt.sh, threat feeds, enrichment, rendering, search, maps, AI, Guard). Keys are never shown.

## Acceptance check (5 minutes)

1. Open `#/check`, paste `https://adcb-secure-login.xyz/login` → **Check it** → FAKE, signals,
   "Saved as finding #N".
2. Paste a suspicious SMS (e.g. a parcel "customs fee" message with a link) → analysis + saved.
3. Open `#/portal` (no login needed from this computer with `make dev`) → **All findings** lists both; filter by verdict / type;
   open each finding: the same verdict, signals, excerpts and checks as in the Checker.
4. Reload the page: both findings are still there, no duplicates.

Automated version: `make e2e PORTAL_USER=… PORTAL_PASS=…` against the running server.

## Official sources (needed for SAFE and for claim verification)

* Approve registry entries after verifying them: `make registry ARGS='approve <id> --reviewer "Name"'`.
* Retrieve official records into the snapshot store: `make registry ARGS="fetch <id>"`
  (approved entries only; network required). The Checker reads only what was actually
  retrieved; without records, government claims are reported as not checked / not verifiable.

## The Guard (live DNS blocking)

* Page: `#/guard`. Stats and the "Newest fakes" list update live over SSE (`guard` events).
* Private DNS hostname: set `NEXTDNS_PROFILE_ID` + `NEXTDNS_API_KEY` (server secrets) — the page then
  shows `<profile>.dns.nextdns.io` and new fakes are pushed to that profile's denylist within
  `GUARD_SYNC_DEBOUNCE_S`. Without them the page says "not configured" (no invented hostname).
* DoH on this server: `GUARD_DOH_ENABLED=1` → `https://<host>/dns-query`.
* Quick checks: `curl -s localhost:8000/api/guard/stats`, `curl -s localhost:8000/api/guard/blocklist.txt`,
  `curl -s -X POST localhost:8000/api/guard/sync`, then `curl -s localhost:8000/api/guard/sync-status`.
* Try it: "Test a domain with Guard + Checker" on the Guard page, then "Preview verdict".
* VPS (AdGuard Home + nginx verdict page): `guard/README.md` Path B; `make guard-sync` (dry run),
  `make guard-sync APPLY=1`.
* Browser test: `make e2e-guard`.

## Truths to state

* A WARNING is "not verified", not "safe". SAFE appears only for an approved, fresh official domain.
* Every Checker result is stored for the portal; personal data is removed from messages first.
* The Guard lists only FAKE (confirmed-malicious) domains. A Checker **link** check that is FAKE is
  listed live (the domain only — the submission, its text and finding id stay in the portal);
  message text never lists anything. WARNING / UNKNOWN / official / shared / widely used sites are
  never blocked. Choose sources with `GUARD_SOURCES`.
* Unofficial prototype — not an Abu Dhabi Police system.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `make: No rule to make target 'user'` | You are not in the project folder (`ls` must show `Makefile`, `backend/`, `web/`). |
| pip asks "User for nexus…" | Your pip.conf uses a private mirror: `make bootstrap PIP_INDEX=https://pypi.org/simple`. |
| `ModuleNotFoundError: fastapi` | Dependencies not installed in `.venv`: run `make bootstrap`. |
| Portal login loops back | HTTPS needed when `APP_ENV=production` (Secure cookie); use `make dev` locally. |
| Checker shows "service can't be reached" | Backend down or wrong `API_BASE` in `web/config.js`. No verdict is shown on failure, by design. |
| Checker 429 | `SCAN_RATE_PER_MIN` reached for that client; wait a minute. |
| Guard page says "Private DNS is not configured" | Set `NEXTDNS_PROFILE_ID` (and `NEXTDNS_API_KEY` for pushes) or `GUARD_DOT_HOSTNAME`, restart. |
| Guard "Sync error" badge | `GET /api/guard/sync-status` shows the provider error (wrong key/profile, 429 rate limit, 5,000-entry limit). |
| `/dns-query` returns 404 | DoH is off: `GUARD_DOH_ENABLED=1`. Clean names answer SERVFAIL if `GUARD_UPSTREAM_DOH` is unreachable. |
| Sweep "failed: no live provider configured" | Set `SEARCH_LIVE_ENABLED=1` (+ `SERPER_API_KEY`) or `MAPS_LIVE_ENABLED=1` + `GOOGLE_PLACES_API_KEY`. |
