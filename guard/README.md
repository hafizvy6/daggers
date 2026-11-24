# Daggers Guard (WS2)

Guard turns WS1's confirmed findings into a DNS blocklist.

| Endpoint | Owner | Purpose |
|---|---|---|
| `GET /api/guard/feed` | WS1 | JSONL `GuardRow` source of truth (unchanged) |
| `GET /api/guard/stats` | WS1 | blocked domains / hits (unchanged) |
| `GET /api/guard/blocklist.txt?format=hosts\|domains` | WS2 | hosts file (`0.0.0.0 domain`) or bare domains |
| `GET /api/guard/sync-status` | WS2 | last sync, counts, exclusions, errors |

**Blocked:** only `MALICIOUS` rows from WS1's feed, valid DNS names, flagged within
`GUARD_MAX_AGE_DAYS` (default 30), never an official-registry or WS1-allowlisted domain.
**Never blocked:** unknown domains, WARNING, MISLEADING (even with WS1's
`GUARD_BLOCK_MISLEADING=1`), unverified reports. If WS1's feed fails, the last good list is
served and `sync-status` reports `stale`.

## NextDNS

1. Create a NextDNS profile; note its ID and an API key (Account → API).
2. Dry run: `python guard/sync_nextdns.py --api http://localhost:8000`
3. Apply: `NEXTDNS_API_KEY=... NEXTDNS_PROFILE=abc123 python guard/sync_nextdns.py --apply`

Alternatively paste `…/blocklist.txt?format=domains` into the profile's denylist by hand.

### Limits — read before demoing
* The script was **not** run against the live NextDNS API from the WS2 build environment.
* WS2 does not read NextDNS analytics. Free-tier logging/analytics retention is limited and
  block events are **not measured** by Daggers; `sync-status` always reports
  `block_events_measured: false`. Never present a block count as measured unless it came from
  the provider's own dashboard.
