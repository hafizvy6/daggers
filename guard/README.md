# Daggers Guard

Guard turns confirmed radar findings into a DNS blocklist. It is integrated into the single backend — no second service.

| Endpoint | Purpose |
|---|---|
| `GET /api/guard/feed` | JSONL `GuardRow` source of truth |
| `GET /api/guard/stats` | blocked domains / hits (plus `blocked_today`, `feed_size`) |
| `GET /api/guard/blocklist.txt?format=hosts\|domains` | hosts file (`0.0.0.0 domain`) or bare domains |
| `GET /api/guard/sync-status` | last sync, counts, exclusions, errors |
| `GET /api/guard/config` | Private DNS hostname for the PWA (from `NEXTDNS_DNS_HOSTNAME` or `NEXTDNS_PROFILE`) |

**Blocked:** only `MALICIOUS` rows from the backend's Guard feed, valid DNS names, flagged within
`GUARD_MAX_AGE_DAYS` (default 30), never an official-registry or allowlisted domain.
**Never blocked:** unknown domains, WARNING, MISLEADING (even with `GUARD_BLOCK_MISLEADING=1`),
unverified reports. If the feed cannot be read, the last good list is served and
`sync-status` reports `stale`. With an empty database the list is empty — not a sample.

## NextDNS

1. Create a NextDNS profile; note its ID and an API key (Account → API).
2. Dry run: `python guard/sync_nextdns.py --api http://localhost:8000`
3. Apply: `NEXTDNS_API_KEY=... NEXTDNS_PROFILE=abc123 python guard/sync_nextdns.py --apply`

Alternatively paste `…/blocklist.txt?format=domains` into the profile's denylist by hand.

### Limits — read before relying on it
* The script should be validated against your own NextDNS profile before unattended use.
* Daggers does not read NextDNS analytics. Free-tier logging/analytics retention is limited and
  block events are **not measured** by Daggers; `sync-status` always reports
  `block_events_measured: false`. Never present a block count as measured unless it came from
  the provider's own dashboard.
* The NextDNS API key lives only on the machine running `sync_nextdns.py`. Never ship it to the
  browser, the PWA, the extension, or your deployment environment beyond that operator machine.
