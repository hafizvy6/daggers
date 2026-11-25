# Daggers — Installation and deployment

> Nothing in this repository has been deployed. These files are deployment *configuration*; the
> Docker image was not built in the development environment (no Docker daemon/network there).
> Do a staging run before relying on it.

## 1. Environments

Daggers has one mode: **live**. There is no demo mode, no seed data and no fixture fallback.

| `APP_ENV` | Use | Behaviour |
|---|---|---|
| `dev` (default) | local development | live; plain-HTTP cookies; API docs at `/docs` |
| `production` | real use | live; Secure cookies + HSTS (HTTPS required); API docs off |

## 2. Local install (dev)

Requirements: Python 3.11+, `make`. Optional: Node 18+ and Google Chrome for the browser tests.

```bash
make bootstrap                    # .venv + requirements.txt (pinned); an existing .venv is kept
# if this machine's pip.conf points at a private mirror that asks for a login:
make bootstrap PIP_INDEX=https://pypi.org/simple
cp .env.example .env              # optional; defaults are safe
make user U=admin R=admin         # password is prompted (min 12 chars)
make dev                          # http://localhost:8000  → portal at #/portal
```

Without HTTPS keep `COOKIE_SECURE=0` (the dev default) or the browser will not send the session cookie.

## 3. Production (Docker Compose + Caddy HTTPS)

Prerequisites: a Linux host with Docker, a DNS A/AAAA record for your domain, ports 80/443 open.

```bash
cp .env.example .env
#   set: DAGGERS_DOMAIN=your.domain   CORS_ORIGINS=https://your.domain
#   optional keys: SERPER_API_KEY, GOOGLE_PLACES_API_KEY, GEMINI_KEY, GROQ_KEY (+ *_ENABLED flags)
chmod 600 .env
docker compose up -d --build
docker compose exec app python -m backend.app.admin_cli create-user --username admin --role admin
curl -fsS https://your.domain/api/healthz
```

* Caddy obtains and renews the TLS certificate automatically (`deploy/Caddyfile`); SSE is not buffered.
* The app container runs as non-root (uid 10001), listens only on the internal network, and
  stores SQLite + evidence in the `daggers-data` volume.
* `uvicorn --proxy-headers` with `FORWARDED_ALLOW_IPS=*` is safe here only because the app port is
  not published; Caddy is the only client. Do not publish port 8000.
* Without Docker: `make prod` behind any HTTPS reverse proxy that forwards `X-Forwarded-For/Proto`.

Then sign in at `https://your.domain/#/login`, create further users in the portal (admin) or with
`admin_cli`, and check `GET /api/readiness` (admin) for the configuration truth.

## 4. Police Portal users

```bash
python -m backend.app.admin_cli create-user  --username alice --role investigator
python -m backend.app.admin_cli set-password --username alice
python -m backend.app.admin_cli disable      --username alice
python -m backend.app.admin_cli list
# non-interactive: echo "$PW" | python -m backend.app.admin_cli create-user --username ci --role viewer --password-stdin
```

Roles: `viewer` (read findings, reports, sweeps, registry) · `investigator` (+ investigate URLs, run
sweeps, file/advance reports, AI analysis) · `admin` (+ users, audit log, mode, readiness).

## 5. Official-source registry approval

All shipped registry entries are `pending`, so **no result is SAFE until a human approves entries**.

```bash
make registry ARGS="list --status pending"
make registry ARGS="show wam"
make registry ARGS='approve wam --reviewer "Full Name"'
make registry ARGS='revoke wam --reviewer "Full Name" --reason "..."'
```

The 15 entries already checked against official sources on 2026-11-24 (evidence in each entry's
`provenance` and in [GOVERNMENT-SAFE.md](GOVERNMENT-SAFE.md) §4) can be approved in one step, after
you have reviewed that evidence:

```bash
make approve-verified
```

**Widely used non-government sites** (YouTube, WhatsApp, Google, …) are SAFE through the independent
reputation check, which needs the Tranco top-sites list. The server downloads it at start-up when it
is missing or older than 7 days (`REPUTATION_AUTO_UPDATE=1`, default; needs outbound HTTPS to
tranco-list.eu and publicsuffix.org). Manually: `make reputation-update`. Status: `/api/readiness`
→ `reputation`. Without a list, those sites are WARNING (fail closed).

The running server picks up registry changes **without a restart** (hot reload; an invalid file
fails closed) and re-tags stored findings, keeping their history. To keep the registry outside the
image (e.g. a writable volume), set `OFFICIAL_REGISTRY_PATH=/data/registry.yaml` for both the app and
`make registry` / `make approve-verified`.

Verify each domain independently (official site, WHOIS/registrar, government directory) before
approving. To verify government claims in Checker messages, retrieve the approved sources' records
into the snapshot store (network required; approved entries only, robots.txt respected):

```bash
make registry ARGS="fetch <id>"     # → backend/data/official_snapshots (OFFICIAL_SNAPSHOT_DIR)
```

The Checker uses only records that were actually retrieved; without them a government claim is
reported as not checked / not verifiable — never as verified. Schedule `fetch` (e.g. cron) to keep
records fresh. The registry lives in `backend/app/channels/official/registry.yaml`: commit the change,
then redeploy (`docker compose up -d --build`). The image copy is read-only to the app user by design.

## 6. External services (all optional, server-side keys only)

| Service | Variables | Without it |
|---|---|---|
| Serper (web search) | `SEARCH_LIVE_ENABLED=1`, `SERPER_API_KEY` | DuckDuckGo HTML fallback; in production no fixtures → sweep may fail honestly |
| Google Places (maps) | `MAPS_LIVE_ENABLED=1`, `GOOGLE_PLACES_API_KEY` | maps sweeps unavailable in production (503/failed) |
| Gemini / Groq (AI Analyst) | `GEMINI_KEY`, `GROQ_KEY` | evidence-only template summary |
| crt.sh, threat feeds, enrichment, render | `CRT_ENABLED`, `FEEDS_ENABLED`, `ENRICH_ENABLED`, `RENDER_ENABLED` (+ Playwright for render) | radar idle in production |
| NextDNS (Guard) | `NEXTDNS_API_KEY`, `NEXTDNS_PROFILE` on the operator machine | blocklist still served at `/api/guard/blocklist.txt` |

Keys are never sent to the browser or extension. Check provider terms before enabling.

## 7. Backups, upgrades and rollback

```bash
# backup (consistent SQLite copy)
docker compose exec app python -c "import sqlite3;s=sqlite3.connect('backend/data/daggers.db');d=sqlite3.connect('backend/data/backup.db');s.backup(d)"
docker compose cp app:/app/backend/data/backup.db ./backup-$(date +%F).db
```

* Schema migrations are additive and run automatically at start-up (`meta.schema_version`).
  Older code ignores the added columns, so rolling back the image is safe for data.
* Rollback: tag each release image (`docker tag daggers-app daggers-app:YYYYMMDD`), and to roll back
  set `image:` to the previous tag (or check out the previous commit) and `docker compose up -d`.
  Restore the backup DB only if data was corrupted.

## 8. Chrome extension

`chrome://extensions` → Developer mode → **Load unpacked** → select `extension/`. In the extension
popup set the backend URL to your deployment (`https://your.domain`). Store publication was not
done: it needs a developer account, privacy policy, icons/screenshots and review. See `extension/README.md`.

## 9. Pre-launch checklist

- [ ] `make check` passes on the release commit
- [ ] staging run behind HTTPS; login, investigate, sweep, report, export verified
- [ ] admin account created; default/test accounts absent
- [ ] registry entries reviewed and approved by a named person
- [ ] `.env` not in git, permissions 600; keys rotated if ever shared
- [ ] backups scheduled; restore tested
- [ ] authorization obtained before using any police name/branding in public
