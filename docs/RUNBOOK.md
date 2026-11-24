# Daggers — Operations & Setup Guide

This is the operational guide for running Daggers for real: cold-start verification, environment configuration, enabling each live adapter, deployment (Docker, Hugging Face Spaces, Cloudflare Pages), the PWA, the guard sync, and incident response. There is no demo mode anywhere; if a table is empty, it is because nothing real has been observed yet.

## 1. Prerequisites

| Requirement | Why |
|---|---|
| Python **3.11+** | backend runtime (3.11–3.14 preferred; 3.15 supported via pinned `Pillow==12.3.0`) |
| Node **18+** | `ops/check_syntax.mjs`, extension unit tests, `make check` |
| SQLite | bundled with Python; WAL mode, no server needed |
| (optional) Playwright/Chromium | only for `RENDER_ENABLED=1` evidence capture |
| (optional) NextDNS account + API key | only for `guard/sync_nextdns.py` |
| (optional) API keys | only for the adapters you enable — each is inert without a flag |

## 2. Cold start (first 5 minutes)

```bash
make bootstrap        # rm -rf .venv && python3.11 -m venv .venv && pip install -r requirements.txt
make verify-empty     # boots a throwaway install against a temp DB; asserts ZERO product data
make dev              # http://localhost:8000 — live app, adapters disabled, honest empty states
```

Expected cold-start responses:

```bash
curl -s localhost:8000/api/healthz
# {"ok": true, "mode": "live", "adapters": {"crt": {"enabled": false, ...}, ...}}

curl -s localhost:8000/api/status
# {"mode":"live","heartbeats":{"crt":-1,"phishtank":-1,"pipeline":-1,"ai":"template"},
#  "counts":{"domains":0,"findings":0,"evidence":0},"uptime_s":...}
```

`-1` heartbeat = the loop has not completed (usually: adapter disabled). Empty feeds are correct until you switch adapters on (§4).

Verify before every deploy:

```bash
make check            # compileall + i18n/design gate + node syntax + extension tests + pytest
```

## 3. Environment configuration (`.env`)

`cp .env.example .env`; `make dev`/`make run` load it. Every variable is optional — the safe default boots a quiet, honest service. **Keys are server-side only.** Never put them in `web/`, the service worker, `localStorage`, the extension, or commits.

### Core paths & limits

| Variable | Default | Meaning |
|---|---|---|
| `APP_ENV` | `production` | environment name (informational) |
| `PORT` | `8000` | HTTP port |
| `DB_PATH` | `backend/data/daggers.db` | SQLite file — persist this volume in deployments (HF Space uses ephemeral storage unless you mount a disk; see §8) |
| `EVIDENCE_DIR` | `backend/data/evidence` | real captured JPGs live here |
| `GALLERY_DIR` | `backend/data/gallery` | operator-supplied perceptual-hash reference images |
| `WEB_DIR` | `web` | static PWA root |
| `CORS_ORIGINS` | localhost origins | comma-separated explicit allowlist |
| `CORS_ORIGIN_REGEX` | — | controlled alternative, e.g. `^https://[a-z0-9-]+\.pages\.dev$` |
| `MALICIOUS_THRESHOLD` / `SUSPICIOUS_THRESHOLD` | `0.65` / `0.35` | verdict cut-offs |
| `RENDER_SCORE_MIN` | `0.45` | minimum triage score before spending a render |
| `AUTOFILE_CLONE_MIN` | `90` | clone % sufficient for auto-filed reports; a confirmed phishing-feed match also suffices |
| `GUARD_BLOCK_MISLEADING` | `0` | `1` also blocks claim-only MISLEADING domains (policy decision) |
| `GUARD_MAX_AGE_DAYS` | `30` | Guard ignores MALICIOUS rows older than this |

### Adapter flags (all default `0`)

| Flag | Effect | Credentials |
|---|---|---|
| `CRT_ENABLED` | poll crt.sh for brand-related certificates | none |
| `FEEDS_ENABLED` | poll OpenPhish + URLhaus; PhishTank if keyed | `PHISHTANK_KEY` (optional) |
| `ENRICH_ENABLED` | RDAP/DNS/TLS/favicon enrichment per finding | none |
| `RENDER_ENABLED` | Playwright screenshot + clone compare + real evidence | needs `make install-render` |
| `SEARCH_LIVE_ENABLED` | Sweep Search channel: Serper if keyed, else DuckDuckGo HTML | `SERPER_API_KEY` (optional) |
| `MAPS_LIVE_ENABLED` | Sweep Maps channel: Google Places Text Search | `GOOGLE_PLACES_API_KEY` (required) |

### Sweep abuse controls

| Variable | Default | Meaning |
|---|---|---|
| `SWEEP_ALLOW_ARBITRARY` | `0` | `1` allows free-text queries (still PII-filtered, 3–120 chars). `0` = canonical queries from `/api/examples` only |
| `SWEEP_RATE_PER_MIN` | `6` | per client IP |
| `SWEEP_MAX_CONCURRENT` | `2` | global in-flight sweeps |

### AI Analyst

| Variable | Default | Meaning |
|---|---|---|
| `AI_STATE` | `template` | `template` (deterministic, safe) or `live` (external provider). Legacy `AI_PROVIDER=gemini\|groq\|template` and `AI_ON=0` are honored |
| `GEMINI_KEY` / `GROQ_KEY` | — | provider chain is Gemini → Groq → template; unset keys are skipped |
| `GEMINI_MODEL` / `GROQ_MODEL` | `gemini-2.0-flash` / `llama-3.3-70b-versatile` | model override |

### NextDNS (operator machine only)

| Variable | Used by | Meaning |
|---|---|---|
| `NEXTDNS_API_KEY` | `guard/sync_nextdns.py --apply` | Account → API key |
| `NEXTDNS_PROFILE` | same | profile id to push the denylist to |
| `NEXTDNS_DNS_HOSTNAME` | the PWA (read-only) | Private DNS hostname shown in the Guard screen (e.g. `abc123.dns.nextdns.io`). Shown instead of `NEXTDNS_PROFILE`-derived default `<profile>.dns.nextdns.io` when set |

## 4. Enabling the radar, step by step

Enable in this order, verifying after each — each stage works with the rest off:

1. **crt.sh** — `CRT_ENABLED=1`. Watch the logs; `GET /api/status` shows `heartbeats.crt` counting down from poll interval. Politeness built-in: ≥20 s between queries, custom UA `Daggers-Research/1.0`. No credential needed. Note crt.sh is free but rate-limited; on 429 the poller backs off and produces no findings.
2. **Phishing feeds** — `FEEDS_ENABLED=1`. OpenPhish and URLhaus need no key. For PhishTank, register at phishtank.com, set `PHISHTANK_KEY`, and keep `http_user_agent` identifiable.
3. **Enrichment** — `ENRICH_ENABLED=1`. Adds RDAP record age (via rdap.org), DNS A records, TLS issuer/first-seen, and a favicon perceptual hash. Timeout-isolated; worst case is missing fields, never a crash.
4. **Renderer** — `make install-render` (installs imagehash, numpy, opencv-headless, playwright; then `playwright install chromium`; on the slim Docker image add `--with-deps` or use `INSTALL_RENDER=1`). Then `RENDER_ENABLED=1`. The renderer loads pages read-only: no downloads, no form fills, no credential submissions, 15 s hard timeout. **Evidence JPGs appear only from now on**, composed side-by-side against the reference capture.
5. **Official references** — the repo intentionally ships no reference screenshots. Build real captures on an operator machine with `python ops/capture_reference.py adnoc.ae adcb.ae` or `python ops/capture_reference.py --all-brands`; files stay under `$GALLERY_DIR` as `reference_<host>.jpg`. Without these, clone detection reports nothing — honestly.

Check the loop end-to-end:

```bash
curl -s localhost:8000/api/healthz   # every enabled adapter shows enabled:true
curl -s 'localhost:8000/api/feed?limit=5'
curl -N  localhost:8000/api/stream   # heartbeat; real findings appear as events
```

## 5. Sweep (Search / Maps)

The endpoint is disabled as a proxy until you opt in:

```bash
# Search: either keyless DuckDuckGo HTML…
SEARCH_LIVE_ENABLED=1
# …or Serper (Google results): set SERPER_API_KEY and keep SEARCH_LIVE_ENABLED=1
# Maps: authorized Google Places key is mandatory
MAPS_LIVE_ENABLED=1 GOOGLE_PLACES_API_KEY=...
```

Canonical queries live in `backend/app/channels/queries.yaml` and are served at `GET /api/examples`. The PWA pills use those by id. Free-text is rejected with 403 unless `SWEEP_ALLOW_ARBITRARY=1`.

Official-registry verification (authority/scope checks for government and bank domains) is a **human** act:

```bash
python -m backend.app.channels.official.cli list --status pending
python -m backend.app.channels.official.cli show <id>
python -m backend.app.channels.official.cli verify "شرطة أبوظبي"        # text against approved entries
python -m backend.app.channels.official.cli approve <id> --reviewer "Your Name"
python -m backend.app.channels.official.cli validate                     # registry sanity
python -m backend.app.channels.official.cli authenticate https://adpolice.gov.ae
# discover new official domains from a saved page (dry run, then --write):
python -m backend.app.channels.official.cli discover --html page.html --source-url https://...
```

Discovery results always land as `pending` and stay untrusted until a named human approves them.

## 6. AI Analyst

Default is the deterministic template (both EN and AR, correct verdict vocabulary, clearly labeled `provider:"template", fallback:true` in API responses). To go live:

```bash
AI_STATE=live GEMINI_KEY=...   # Gemini first
GROQ_KEY=...                   # used when Gemini is unset/fails/disabled
```

The model only ever sees `Report.evidence` (the canonical Finding object). The privacy filter drops anything outside the contract (names, phones, messages) before a prompt is built; the model cannot and is never allowed to write `verdict`, `score`, or `reasons`. If both providers fail mid-stream, the SSE stream still terminates with a `final` event carrying the template output.

## 7. Guard / NextDNS

The Guard screen in the PWA renders whatever the backend reports; it is empty until confirmed fakes exist. To push the list to NextDNS you run the sync on an **operator machine** (not in the app server, never in the browser):

```bash
python guard/sync_nextdns.py --api https://your-api.example     # dry run — prints what would change
NEXTDNS_API_KEY=... NEXTDNS_PROFILE=abc123 \
  python guard/sync_nextdns.py --api https://your-api.example --apply
# optional: remove domains this script previously added that are no longer listed
python guard/sync_nextdns.py --api https://your-api.example --apply --prune
```

* Only `MALICIOUS`, valid DNS names, flagged within `GUARD_MAX_AGE_DAYS`, and never official-registry/allowlisted domains are pushed.
* Block events are **not measured** — `GET /api/guard/sync-status` reports `block_events_measured: false`; read counts from the NextDNS dashboard only.
* For iPhone/Android "Private DNS", set `NEXTDNS_DNS_HOSTNAME=abc123.dns.nextdns.io` so the PWA shows the exact setup host.

## 8. Deployment

### Docker (single container, one process)

```bash
docker build -t daggers .
docker run -p 8000:8000 --env-file .env -v daggers-data:/app/backend/data daggers
# with the renderer:
docker build --build-arg INSTALL_RENDER=1 -t daggers-render .
```

`requirements.txt` is deliberately light; heavy wheels only install via `--build-arg INSTALL_RENDER=1` or `make install-render`. The image bundles no data — the first request initializes an empty schema. Mount `/app/backend/data` or every restart loses observations.

### Hugging Face Spaces / any Python host

1. Space SDK = Docker (or Python 3.11), port 8000.
2. Set secrets in the Space settings (never commit): `CRT_ENABLED=1`, `FEEDS_ENABLED=1`, `ENRICH_ENABLED=1`, keys as needed, `AI_STATE=live` + `GEMINI_KEY`.
3. Persistence: HF Space disk is ephemeral. Either accept a quiet cold start (the app re-initializes empty every boot — safe) or mount a dataset/bucket at `backend/data` and set `DB_PATH` accordingly.

### Cloudflare Pages (static PWA) + remote API

1. Edit `web/config.js` **once**: `window.API_BASE = "https://your-host.example"`.
2. On the API host set `CORS_ORIGINS=https://<project>.pages.dev,https://<custom-domain>` (or a narrow `CORS_ORIGIN_REGEX`).
3. Deploy `web/` as a static site (Pages "build output directory" = `web`). The service worker registers from same origin; the PWA is then installable.
4. Verify: open the Pages URL, DevTools → Application → Service Workers = activated; Network = `/api/healthz` 200 with your origin in `access-control-allow-origin`.

For uptime probes, point UptimeRobot (or equivalent) at `https://your-host.example/api/healthz` — it needs no key and returns adapter readiness.

### systemd unit (bare VM)

```ini
[Unit]
After=network.target
[Service]
WorkingDirectory=/opt/daggers
Environment=PYTHONPATH=/opt/daggers
EnvironmentFile=/opt/daggers/.env
ExecStart=/opt/daggers/.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
Restart=always
[Install]
WantedBy=multi-user.target
```

## 9. PWA & extension

**PWA**: served at `/`. Install from the browser menu; EN/AR with full RTL. iOS requires Safari → Share → Add to Home Screen. The service worker is network-first for `/api/*` (last-good real response is reused offline) and cache-first for the app shell. `web/evidence/` screenshots are *not* shipped — evidence loads live.

**Extension** (`extension/`): `chrome://extensions` → Developer mode → Load unpacked → pick `extension/`. Point it at the API origin from the popup (default `http://localhost:8000`; HTTPS required for anything else; Chrome grants one origin at a time). Labels come only from the backend; failure/timeout/unknown → grey `NOT CHECKED`, never green. Run its tests with `node --test extension/tests/core.test.js`.

## 10. Routine maintenance

```bash
make snapshot    # DB + evidence into ./snapshot/ (not committed; use for backups/USB)
make clean       # delete local SQLite + captured imagery (destructive; fresh empty boot after)
python3 ops/verify_empty.py   # post-deploy sanity: the running code carries no product data
python -m backend.app.channels.official.cli validate   # registry sanity after edits
```

Rotate any key you suspect leaked by re-issuing it with the provider — nothing in the browser or extension holds keys to rotate separately.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Feed is `[]`, counts 0 | Expected with no adapters enabled. Enable §4 one at a time; check `/api/healthz`. |
| Heartbeats show `-1` | Loop never completed: adapter disabled, or first poll still in flight (`CRT_MIN_QUERY_GAP_S`). |
| `/api/healthz` shows adapters enabled but no data | Provider outage or empty result set. Check logs; enable `ENRICH_ENABLED` for detail; never paste real victim data to "test". |
| `403` from `/api/sweep` | Free-text query with `SWEEP_ALLOW_ARBITRARY=0` — pick a canonical pill or set the flag. |
| `429` from `/api/sweep` | Per-IP rate limit; tune `SWEEP_RATE_PER_MIN`. |
| `422` on `/api/mode` with `demo` | Correct — demo mode does not exist. Only `live` is accepted. |
| PWA shows UNAVAILABLE chip | API unreachable/down or offline. Check `web/config.js` `API_BASE` and CORS on the API host. |
| `make bootstrap` on macOS Python 3.15 fails building wheels | Use python3.11–3.14, or ensure current `requirements.txt` (Pillow 12.3.0 ships cp315 wheels). |
| Evidence 404 for an id you expect | A finding only has evidence when the live renderer captured one. `RENDER_ENABLED=0` ⇒ all evidence 404s — by design. |
| crt.sh empty / 429-heavy | Rate limited. Keep `CRT_MIN_QUERY_GAP_S ≥ 20`; lower `CRT_POLL_INTERVAL_S` is counterproductive. |
| AI always `template` | `AI_STATE` not `live`, both keys unset, or provider errors — check logs for `ai_provider_failed`. |
| NextDNS sync prints nothing | Feed is empty (no confirmed fakes) — nothing to push. `--apply` with an empty list is a no-op, not an error. |

## 12. Safety reminders

- Never paste real victim messages into a report, prompt, or commit. The Checker accepts any text but persists none of it.
- Reports contain the crime, not the victim — `validate_zero_pii` enforces the allowlist at build time.
- AI may explain evidence but never sets `verdict`, `score`, or `reasons`.
- The renderer never submits a form; non-read requests are aborted.
- Test doubles and sample payloads live only under `backend/tests/` and are never loaded by the app.
