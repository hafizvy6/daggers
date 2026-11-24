# Daggers — Integrated API Reference

Interactive OpenAPI is served at `/docs`; the machine schema is at `/openapi.json`. WS1 provides the deterministic core contracts; WS2 and WS3 add sweep, Guard sync, portal, and AI routes. The offline demo path works with no external network or API keys.

## Endpoints

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/status` | — | `Status` |
| GET | `/api/mode` | — | `{"mode":"live"|"demo"}` |
| POST | `/api/mode` | `{"mode":"live"|"demo"}` | `{"mode":"live"|"demo"}` |
| GET | `/api/healthz` | — | health probe |
| GET | `/api/feed?limit=50` | `limit` 1–200 | `[Finding]` newest first |
| GET | `/api/finding/{id}` | — | `Finding` or 404 |
| GET | `/api/evidence/{id}.jpg` | — | JPEG evidence |
| GET | `/evidence/{id}.jpg` | — | same JPEG via static mount |
| POST | `/api/scan` | `ScanRequest` | `ScanResult` |
| GET | `/api/stream` | — | SSE `finding`, `sweep`, `heartbeat` |
| GET | `/api/guard/feed` | — | JSONL `GuardRow` |
| GET | `/api/guard/stats` | — | blocked domains / hits |
| GET | `/api/finding/{id}` WS3/WS2 optional | — | routers mounted defensively when files exist |

## `Finding` — C1

```json
{
  "id": 42,
  "domain": "adcb-secure-login.xyz",
  "verdict": "MALICIOUS",
  "score": 0.93,
  "reasons": ["brand typo/name 'adcb' (distance 0) outside adcb.ae", "cert age 42m", "form posts to foreign host"],
  "cert_issued": "2026-11-24T07:58:00Z",
  "first_seen": "2026-11-24T08:01:00Z",
  "source": "crt.sh",
  "clone": 97,
  "evidence_url": "/evidence/42.jpg",
  "gallery_match": "adcb.ae/login",
  "is_case_file": false
}
```

`verdict` is one of `UNKNOWN`, `SUSPICIOUS`, `MISLEADING`, `MALICIOUS`. UI tags: `SAFE`, `WARNING`, `MISLEADING`, `FAKE`.

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
  "evidence_url": "/evidence/42.jpg",
  "scam_type": "fake-banking-login",
  "offline_capable": true
}
```

`kind`: `url | text | number`. `lang`: `en | ar`. For `text`, URLs are extracted and the original text is also passed through claim rules. For `number`, `core/numbers.py` uses a 200-entry offline reported-number seed plus premium/VoIP/repeat patterns. User input is never persisted.

## `Status`

```json
{
  "mode": "demo",
  "heartbeats": {"crt": 0, "phishtank": 0, "pipeline": 0, "ai": "template"},
  "counts": {"domains": 6, "findings": 6, "evidence": 4},
  "uptime_s": 42
}
```

Heartbeat integers are **seconds since the last real loop completion**; `-1` means no beat yet. `ai` is honestly `template` until WS3 mounts its AI router or `AI_STATE=ok` is set.

## `GuardRow` — C6

```text
{"domain":"evil.xyz","verdict":"MALICIOUS","reason":"brand typo + fresh cert","flagged_at":"2026-11-24T08:03:00Z"}
```

One line per domain, `application/x-ndjson`, newest evidence only. Default policy includes `MALICIOUS`; `GUARD_BLOCK_MISLEADING=1` adds claim-only `MISLEADING` rows. Unicode domains are emitted in punycode wire form.

## `Report` — C4

```json
{
  "id": 7,
  "finding_id": 42,
  "evidence": { "…": "exact Finding object" },
  "status": "QUEUED|SUBMITTED|SEEN",
  "auto": true,
  "filed_at": null,
  "blocked_hits": 1243
}
```

The recursive validator rejects keys containing `user`, `name`, `phone`, `email`, `message`, `input`, `body`, `contact`, `location`, `device`, `sender`, and related tokens, plus contact-like string values. WS3 serves portal/AI routes; WS1 stores and exports the bundle via `reports/queue.py`.

## SSE

`GET /api/stream` emits an immediate heartbeat, then real `finding` events from the radar and periodic status heartbeats. WS2 may call `runtime.publish("sweep", payload)` to emit a `sweep` event. Payload JSON is compact and contains no user data.

```text
event: heartbeat
data: {"mode":"demo", ...}

event: finding
data: {"id":42, ...}
```

## Errors and limits

- `404` for unknown finding/evidence IDs.
- Pydantic `422` for invalid `kind`, `lang`, or mode.
- `limit` is clamped by validation to 1–200.
- Exact C1/C2/C4/C6 JSON is normalized in `db/repo.py` and `reports/builder.py`; no internal `l1_detail` or normalization fields leak into contracts.


## Integrated WS2/WS3 endpoints

| Method | Path | Lane | Response |
|---|---|---|---|
| GET | `/` | WS3 | bilingual PWA shell |
| GET | `/share` | WS3/WS1 seam | PWA `share_target` landing → `#/check` |
| GET | `/api/examples` | WS3/WS1 seam | demo query/example fixtures |
| POST | `/api/sweep` | WS2 | `SweepRun` from Search/Maps fixtures |
| GET | `/api/sweep/{id}` | WS2 | stored `SweepRun` |
| GET | `/api/guard/blocklist.txt` | WS2 | hosts/domains blocklist from WS1 Guard feed |
| GET | `/api/guard/sync-status` | WS2 | sync health and honest NextDNS limitations |
| GET | `/api/reports` | WS3 | `{"reports":[Report...]}` from WS1 SQLite |
| GET | `/api/reports/{id}` | WS3 | one `Report` |
| POST | `/api/reports` | WS3 | file report from `finding_id` or `domain` |
| POST | `/api/reports/{id}/advance` | WS3 | `QUEUED → SUBMITTED → SEEN` |
| GET | `/api/reports/{id}/export` | WS3 | evidence-pack JSON download |
| POST | `/api/report/{id}/analysis` | WS3 | SSE `delta` events + `final` EN/AR summary |
| POST | `/api/report/{id}/takedown` | WS3 | `{letter_en}` takedown draft |

`GET /api/guard/stats` keeps WS1 keys `blocked_domains`, `blocked_hits`, and `mode`, and adds WS3 aliases `blocked_today` and `feed_size`.

The exact WS1 `ScanRequest` remains `{kind,input,lang}`; `kind` is authoritative, not the technical-spec C2 `input_type` wording. WS3's `api.js` has been wired to that shape. AI endpoints receive only canonical `Report.evidence` from the repository and never modify `verdict`, `score`, or `reasons`.
