# Daggers Guard

The Guard turns Daggers' confirmed scams into DNS blocking, live.

```
Checker (link checks) ─┐
Radar   (crt.sh, feeds) ├─► one verdict (trust policy) ─► Guard eligibility ─► SQLite guard_blocklist
Sweep   (search, maps) ─┘                                                     │
Investigations (portal) ┘                                                     ▼
                                    O(1) in-memory index ──► /dns-query (DoH), /api/guard/check
                                             │                /api/guard/verdict, lists, stats
                                             └─► debounced sync ─► NextDNS denylist (Path A)
                                                               └─► AdGuard Home via guard/sync.py (Path B)
                                    SSE `guard` events ─► the Guard page updates live
```

## What is blocked — strict

* **Only `FAKE`** (engine verdict `MALICIOUS` through the central trust policy). With
  `GUARD_INCLUDE_MISLEADING=1`, also `MISLEADING` sites that a government record **contradicts**.
* **Never:** `WARNING`, `UNKNOWN`, `SAFE`, IP addresses, invalid names, government zones,
  official-registry domains (any status), catalog/brand official domains, shared platforms
  (e.g. `github.io`, `vercel.app` — only the exact sub-site would ever be listed) and widely used
  sites from the reputation list. A protected domain already on the list is removed at once.
* **Checker:** only link checks (`input_type` url/domain) list a domain; message text never does.
  The citizen's submission, finding id and text stay portal-only — only the domain is published.
* Entries expire after `GUARD_MAX_AGE_DAYS` (default 30) without a new confirming analysis.
* Which sources may list a domain: `GUARD_SOURCES` (default `radar,sweep,checker,investigation,seed`).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/guard/feed` | JSONL `{domain, verdict, reason, flagged_at}` (unchanged contract) |
| `GET /api/guard/blocklist.txt?format=hosts\|domains` | hosts file / bare domains, weak `ETag` + `304`, `Cache-Control` |
| `GET /api/guard/domains.txt` | one domain per line (routers, NextDNS, AdGuard) |
| `GET /api/guard/adguard-rules.txt` | `\|\|domain^`, or `\|\|domain^$dnsrewrite=NOERROR;A;<GUARD_VERDICT_IP>` |
| `GET /api/guard/stats` | status, mode, DoT hostname, DoH/blocklist URLs, counts, newest fakes, sync health |
| `GET /api/guard/sync-status` | provider push results, errors, rate limits |
| `POST /api/guard/sync` | sync now (`429` + `Retry-After` during the cooldown) |
| `GET /api/guard/check?domain=&live=1` | O(1) lookup; `live=1` also runs the Checker engine on `https://domain/` |
| `GET /api/guard/verdict?domain=&hit=1` | verdict-page data; `hit=1` counts one anonymous block |
| `GET /verdict?domain=` | bilingual verdict page |
| `GET/POST /dns-query` | RFC 8484 DoH (`GUARD_DOH_ENABLED=1`) |

Blocked counters (`blocked_today`, `blocked_total`) count **real** blocks seen by this server:
DoH answers that were blocked and verdict-page visits. Nothing is invented. NextDNS's own
denylist count (last 24 h, from its analytics API) is shown separately when configured.

## Path A — free (no VPS): Hugging Face / Render + NextDNS + DoH

1. Deploy Daggers (see `docs/DEPLOYMENT.md`). Set `GUARD_PUBLIC_ORIGIN=https://<your-app>`.
2. Create a NextDNS profile. Put its ID and an API key (Account → API) in the host's secrets:
   `NEXTDNS_PROFILE_ID`, `NEXTDNS_API_KEY`. Never commit them.
3. The Guard page now shows the real Private DNS hostname `<profile>.dns.nextdns.io`. New fakes
   are pushed to the profile's denylist within `GUARD_SYNC_DEBOUNCE_S` seconds; Daggers only
   ever removes entries it added itself.
4. Phones: Android → Settings → Network → Private DNS → hostname. iPhone: install a NextDNS
   configuration profile (apple.nextdns.io) for that profile.
5. Optional: `GUARD_DOH_ENABLED=1` serves DoH at `https://<your-app>/dns-query` (browsers or apps
   that accept a DoH URL). Blocked → NXDOMAIN (or `0.0.0.0` with `GUARD_DOH_BLOCK_MODE=zero`);
   everything else is forwarded to `GUARD_UPSTREAM_DOH`. Client IPs and query names are not logged.

**Limits:** NextDNS denylists hold at most 5,000 entries; its API rate limits are not published
(Daggers backs off on `429`). Phones see NextDNS's plain block page, not the Daggers verdict page.
Android Private DNS needs a DoT hostname — Daggers on HF/Render cannot serve DoT (port 853), which
is why NextDNS is used here.

## Path B — VPS: AdGuard Home + nginx verdict server

1. Install AdGuard Home on the VPS; merge `AdGuardHome.yaml.example` into its config
   (DoT on 853 with a real certificate for your guard hostname).
2. Feed the list, either:
   * filter URL: `GUARD_SYNC_MODE=filter-url python guard/sync.py --once --apply` (AdGuard Home
     also re-downloads hourly), or
   * live: `ADGUARD_USER=… ADGUARD_PASSWORD=… python guard/sync.py --apply --interval 60`
     (`rules` mode keeps your own custom rules; `rewrites` mode needs `GUARD_VERDICT_IP`).
   Without `--apply` it is a dry run.
3. Set `GUARD_VERDICT_IP` to the VPS IP and use `nginx-verdict.conf`: blocked names resolve to the
   VPS, plain-HTTP visits are redirected to `/verdict?domain=…&hit=1`.

**Limits:** HTTPS visits to a blocked domain cannot show the branded page — no server can hold a
valid certificate for the scam domain — so the browser shows a connection/certificate error
instead. The scam still never loads.

## Legacy

`guard/sync_nextdns.py` (manual, dry run by default) still works for operators who prefer to push
from their own machine instead of letting the server do it.

## Honesty

The NextDNS and AdGuard Home integrations are tested against mocked APIs. They were **not** run
against the live services from the build environment (no internet there). Verify with your own
profile before a demo: `POST /api/guard/sync` then check `GET /api/guard/sync-status`.
