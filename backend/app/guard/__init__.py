"""The Guard — live DNS block list built from the ONE verdict authority (core/ + trust policy).

* eligibility.py  — strict rule: who may ever be blocked (confirmed FAKE only; never official,
                    registry, shared-platform, widely used or government-zone domains)
* index.py        — O(1) in-memory block index (exact host + safe parent-domain match)
* manager.py      — live loop: Checker / Radar / Sweep / Investigation → index + DB → debounced sync
                    → providers + SSE
* nextdns.py      — NextDNS denylist push + (optional) analytics
* doh.py          — RFC 8484 DNS-over-HTTPS resolver (/dns-query)
"""
