# Daggers — live scam checker and Police Portal

> **We catch it, we prove it, we report it.**
>
> *Unofficial prototype built for the SCAMSHIELD AI Hackathon (Abu Dhabi Police × 42 Abu Dhabi).
> It is **not** an Abu Dhabi Police or UAE government system and has no access to police systems.*

Daggers runs in **one mode: live**. There is no demo mode, no seed data and no fixture
fallback. A fresh install is empty; everything shown comes from the real backend.

## The live Checker → Police Portal flow

```
Checker (#/check)  ── POST /api/check ──▶  validate · classify (URL/domain or message) · normalise
                                            │
                                            ▼
                         intelligence engine (core/scorer + core/message)
                         URL/domain heuristics · brand & government impersonation · homographs ·
                         phishing lures · fee/OTP/urgency/delivery message analysis · claims
                                            │
                                            ▼
                         central verdict policy (channels/trust_policy)
                         official-registry authentication · official-source claim verification
                                            │
                                            ▼
                         evidence (every signal + the part of the input that triggered it)
                         personal data removed from messages → SQLite finding (source "checker")
                                            │
                    ┌───────────────────────┴──────────────────────┐
                    ▼                                              ▼
        Checker shows the stored finding              Police Portal (#/portal → All findings)
        (verdict, score, signals, checks,             search · verdict / type / source / date filters ·
         authentication, verification,                open finding → identical analysis · reports ·
         precautions)                                 AI Analyst · export
```

Verdicts: **SAFE** only for an approved, fresh official-registry domain with nothing suspicious ·
**WARNING** unknown, unverified, unavailable or suspicious-but-unconfirmed · **MISLEADING**
government claims contradicted by or not verifiable against approved sources · **FAKE**
sufficiently supported fraud, phishing or impersonation. A failed check never shows SAFE — or
any verdict.

## Run it

```bash
make bootstrap                    # Python 3.11+ → .venv with pinned dependencies
#   behind a private pip mirror:  make bootstrap PIP_INDEX=https://pypi.org/simple
make dev                          # http://localhost:8000
```

* Checker: `http://localhost:8000/#/check`.
* Police Portal: `http://localhost:8000/#/portal` → **All findings**. With `make dev`, a browser on
  the **same computer** opens the portal directly as a local admin — no account, no login
  (`LOCAL_OPEN_ACCESS`, development only; forced off with `APP_ENV=production`).
* Accounts for other computers or production: `make user U=alice R=investigator`, then sign in at `#/login`.
* Roles: `viewer` (read) · `investigator` (+ investigations, reports, AI, sweeps) · `admin` (+ users, audit).

Production (Docker + Caddy HTTPS): **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Official sources

Every registry entry ships as `pending`: nothing is SAFE until a named person approves it.

```bash
make registry ARGS="list --status pending"
make registry ARGS='approve wam --reviewer "Full Name"'   # only after verifying the domain
make registry ARGS="fetch wam"                             # retrieve official records (network)
```

## Tests

```bash
make check                                   # backend (262) + extension (9) + i18n/syntax gates
make e2e PORTAL_USER=… PORTAL_PASS=…         # real-browser acceptance test against a running server
make verify-empty                            # a fresh install contains no product data
```

Results and gaps: **[docs/TESTING-REPORT.md](docs/TESTING-REPORT.md)**.

## Documentation

| Document | Contents |
|---|---|
| [docs/CHECKER.md](docs/CHECKER.md) | the live Checker: what changed, modified files, limitations |
| [docs/CHECKER-ACCURACY.md](docs/CHECKER-ACCURACY.md) | domain age (RDAP), URL/identity, page and feed checks, claim attributes, reason codes, evidence freshness |
| [docs/GOVERNMENT-SAFE.md](docs/GOVERNMENT-SAFE.md) | government authentication + SAFE policy 2.1: root causes, verified domains, approval step, widely-used-site reputation path, tests |
| [docs/API.md](docs/API.md) | API contract |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | architecture, data flows, database |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | install, production, users, registry, rollback |
| [docs/SECURITY.md](docs/SECURITY.md) | security controls and limitations |
| [docs/TESTING-REPORT.md](docs/TESTING-REPORT.md) | what was tested, results, what was not |
| [docs/INTEGRATION-REPORT.md](docs/INTEGRATION-REPORT.md) | how WS1/WS2/WS3 were merged; readiness matrix |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | operations, acceptance check, troubleshooting |
| [docs/WS2.md](docs/WS2.md) | trust policy, registry, verification engine, channels, Guard |
| [extension/README.md](extension/README.md) · [guard/README.md](guard/README.md) | Chrome extension · Guard/NextDNS |
