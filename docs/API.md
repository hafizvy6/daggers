# Daggers — API Reference

Interactive OpenAPI is served at `/docs`; the machine schema is at `/openapi.json`. All routes are live: there is no demo mode. A cold, empty database serves honest empty responses (`[]`, zero counts, empty JSONL/blocklists) until a real finding exists.

## Endpoints

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/status` | — | `Status` |
| GET | `/api/mode` | — | `{"mode":"live"}` |
| POST | `/api/mode` | `{"mode":"live"}` | `{"mode":"live"}` (anything else → 422) |
| GET | `/api/healthz` | — | `{ok, mode, adapters{}}` — no secrets |
| GET | `/api/feed?limit=50&min_score=0.35` | `limit` 1–200; `include_unknown=true` + `include_suppressed=true` for analyst view | `[Finding]` newest first; CT-only `UNKNOWN` and analyst-suppressed domains hidden by default |
| GET | `/api/finding/{id}` | — | `Finding` or 404 |
| GET | `/api/finding/{id}/label` | — | `{"domain":…,"label":"official|scam|unrelated|parked"|"label":null …}` |
| POST | `/api/finding/{id}/label` | `{"label":"official|scam|unrelated|parked"}` | latest analyst label; official/unrelated/parked are suppressed from the default feed |
| GET | `/api/evidence/{id}.jpg` | — | real captured JPEG or 404 |
| GET | `/evidence/{id}.jpg` | — | same JPEG via static mount |
| POST | `/api/scan` | `ScanRequest` | `ScanResult` |
| GET | `/api/stream` | — | SSE `finding`, `sweep`, `heartbeat` |
| GET | `/api/guard/feed` | — | JSONL `GuardRow` |
| GET | `/api/guard/stats` | — | blocked domains / hits (+ `blocked_today`, `feed_size`) |
| GET | `/api/guard/config` | — | `{hostname, configured}` for Private DNS |
| GET | `/api/guard/blocklist.txt` | — | 0.0.0.0-prefixed host list for the sync script |
| GET | `/api/guard/sync-status` | — | sync health and honest NextDNS limitations |
| GET | `/api/examples` | — | canonical sweep query presets; empty check/number sets |
| POST | `/api/sweep` | `SweepRequest` | `SweepRun` (empty results when unconfigured) |
| GET | `/api/sweep/{id}` | — | stored `SweepRun` or 404 |
| GET | `/api/reports` | — | `{"reports":[Report…]}` |
| GET | `/api/reports/{id}` | — | one `Report` |
| POST | `/api/reports` | `{finding_id}` or `{domain}` | file report; 201 on create, 200 on idempotent re-file |
| POST | `/api/reports/{id}/advance` | `{"status":"QUEUED"|"SUBMITTED"|"SEEN"}` | advanced `Report` |
| GET | `/api/reports/{id}/export` | — | evidence-pack JSON download |
| POST | `/api/report/{id}/analysis` | — | SSE `delta` events + `final` EN/AR summary |
| POST | `/api/report/{id}/takedown` | — | `{letter_en}` takedown draft |
| GET | `/` | — | bilingual PWA shell |
| GET | `/share` | — | PWA `share_target` landing → `#/check` |

## `Finding` — C1

```json
{
  "id": 1,
  "domain": "example-scam.example",
  "verdict": "MALICIOUS",
  "score": 0.93,
  "reasons": ["brand typo/name 'adcb' (distance 0) outside adcb.ae", "cert age 42m", "form posts to foreign host"],
  "cert_issued": "2026-11-24T07:58:00Z",
  "first_seen": "2026-11-24T08:01:00Z",
  "source": "crt.sh",
  "clone": 97,
  "evidence_url": "/evidence/1.jpg",
  "gallery_match": "adcb.ae/login",
  "is_case_file": false
}
```

`verdict` is one of `UNKNOWN`, `SUSPICIOUS`, `MISLEADING`, `MALICIOUS`. UI tags: `SAFE`, `WARNING`, `MISLEADING`, `FAKE`. `evidence_url` is `null` unless a live renderer stored a real capture.

## `ScanRequest` / `ScanResult` — C2

```json
// request
{"kind": "url", "input": "https://adcb-secure-login.xyz/login", "lang": "en"}

// response
{
  "kind": "url",
  "input": "https://adcb-secure-login.xyz/login",
  "verdict": "MALICIOUS",
  "score": 0.95,
  "reasons": ["risky low-cost TLD .xyz", "brand typo/name 'adcb' (distance 0) outside adcb.ae"],
  "evidence_url": null,
  "scam_type": "fake-banking-login",
  "offline_capable": true
}
```

`kind`: `url | text | number`. `lang`: `en | ar`. For `text`, URLs are extracted and the original text is also passed through claim rules. For `number`, `core/numbers.py` applies a 200-entry deterministic catalog of premium/VoIP/repeat patterns plus normalization. User input is never persisted.

## `Status`

```json
{
  "mode": "live",
  "heartbeats": {"crt": -1, "phishtank": -1, "pipeline": -1, "ai": "template"},
  "counts": {"domains": 0, "findings": 0, "evidence": 0},
  "uptime_s": 42
}
```

Heartbeat integers are **seconds since the last real loop completion**; `-1` means the loop has not completed a pass yet (or that adapter is disabled). `ai` is honestly `template` until `AI_STATE=live` with a provider key.

## `GuardRow` — C6

```text
{"domain":"evil.example","verdict":"MALICIOUS","reason":"brand typo + fresh cert","flagged_at":"2026-11-24T08:03:00Z"}
```

One line per domain, `application/x-ndjson`. Default policy includes `MALICIOUS`; `GUARD_BLOCK_MISLEADING=1` adds claim-only `MISLEADING` rows. Unicode domains are emitted in punycode wire form.

## `Report` — C4

```json
{
  "id": 7,
  "finding_id": 1,
  "evidence": { "…": "exact Finding object" },
  "status": "QUEUED|SUBMITTED|SEEN",
  "auto": true,
  "filed_at": null,
  "blocked_hits": 0
}
```

The recursive validator rejects keys containing `user`, `name`, `phone`, `email`, `message`, `input`, `body`, `contact`, `location`, `device`, `sender`, and related tokens, plus contact-like string values.

## SSE

`GET /api/stream` emits an immediate heartbeat, then real `finding` events from the radar and periodic status heartbeats. Sweep requests publish a `sweep` event. Payload JSON is compact and contains no user data.

```text
event: heartbeat
data: {"mode":"live", ...}

event: finding
data: {"id":1, ...}
```

## Errors and limits

- `404` for unknown finding/evidence/report/sweep ids.
- Pydantic `422` for invalid `kind`, `lang`, mode, channel, or status.
- `403` when `POST /api/sweep` is sent a free-text query but `SWEEP_ALLOW_ARBITRARY=0`. The default path accepts the server's canonical queries (`/api/examples`) only.
- `429` when the sweep per-IP rate limit (`SWEEP_RATE_PER_MIN`, default 6/min) or the concurrency cap (`SWEEP_MAX_CONCURRENT`) is exceeded.
- `limit` on `/api/feed` is clamped by validation to 1–200.
- Exact C1/C2/C4/C6 JSON is normalized in `db/repo.py` and `reports/builder.py`; no internal normalization fields leak into contracts.

## Integration notes

- AI endpoints receive only canonical `Report.evidence` from the repository and never modify `verdict`, `score`, or `reasons`.
- `/api/status` exposes only monotonic ages and counts — no configuration values, no keys, no hostnames beyond what `/api/guard/config` deliberately publishes for the PWA's setup instructions.
- CORS is an explicit origin allowlist from `CORS_ORIGINS` (plus optional `CORS_ORIGIN_REGEX` for controlled Pages previews). The PWA calls same-origin by default; set `window.API_BASE` in `web/config.js` when serving the PWA from a separate static host.
