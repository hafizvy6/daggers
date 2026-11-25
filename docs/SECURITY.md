# Daggers — Security controls and limitations

## Controls implemented (and covered by tests unless marked)

**Authentication & sessions** (`backend/app/security.py`, `api/auth.py`)
* Passwords: scrypt (n=2^14, r=8, p=1, random salt), minimum 12 characters; constant-time compare;
  dummy hash for unknown users so timing does not reveal valid usernames.
* Session token: 32 random bytes; only its SHA-256 is stored; cookie `daggers_session` is HttpOnly,
  SameSite=Strict, Secure in production; server-side expiry (`SESSION_TTL_HOURS`, default 12);
  logout and account disable revoke sessions.
* Login lockout: `LOGIN_MAX_FAILURES` (5) per username and per client IP in a 15-minute window → 429.
* No default accounts. First admin is created on the host with `admin_cli` (password prompted or stdin).

**Local open access (development convenience)** — `LOCAL_OPEN_ACCESS=1` (set by `make dev`) treats
a browser on the same computer as a local admin without signing in. It applies only to requests whose
peer address is loopback **and** that carry no proxy headers (`X-Forwarded-For`, `X-Real-IP`,
`Forwarded`), is forced off when `APP_ENV=production`, logs a warning at start-up, and still requires
the CSRF token (per process, readable only same-origin via `/api/auth/me`) for every change. Actions
are audited as user `local`. Do not use it on a shared machine.

**Authorization & CSRF**
* Roles `viewer < investigator < admin` enforced server-side on every protected route
  (see `docs/API.md`). Frontend gating is cosmetic only.
* CSRF: state-changing authenticated requests require the `X-CSRF-Token` header bound to the session,
  in addition to SameSite=Strict.
* Investigation findings (`source=investigation`) are private: excluded from the public feed, the SSE
  stream and Guard; `/api/finding/{id}` and its evidence require `viewer`.

**Audit** — logins (success/failure), logouts, user create/disable, mode changes, investigations,
sweeps, report filing/advancement/export and AI runs are written to `audit_log` (actor, action, target, IP, time).

**Input & output**
* Pydantic validation with length limits on every body; URLs normalised, non-http(s) rejected,
  tracking parameters removed.
* All SQL is parameterised and confined to `backend/app/db/repo.py` (enforced by a test).
* Frontend renders backend data with `textContent`/escaping; external links are `https:` only and
  `rel="noopener noreferrer"`.
* Security headers on every response: CSP (`script-src 'self'`, `frame-ancestors 'none'`,
  `object-src 'none'`), X-Frame-Options DENY, nosniff, Referrer-Policy no-referrer,
  Permissions-Policy, COOP; HSTS in production.
* CORS applies only to public credential-less endpoints (`allow_credentials` off); the portal is same-origin.

**Live Checker** (`POST /api/check`, public)
* Input validated server-side (length ≤ 4000, http/https only; `javascript:`, `data:`, `file:` refused).
* Submitted URLs are **never fetched** by the Checker: analysis is lexical/structural plus the
  official-registry lookup, so the Checker cannot be used for server-side request forgery.
* Personal data is removed from messages **before storage** (phone numbers, e-mail addresses,
  Emirates ID, IBAN, Luhn-valid card numbers) — in the stored text and in every evidence excerpt.
* Checker findings are private to the Police Portal (viewer+); never in the public feed, the SSE
  stream or the Guard DNS blocklist (public submissions must not trigger blocking).
* Rate limit per client (`SCAN_RATE_PER_MIN`); duplicate protection by client request id and by
  identical input from the same client within `CHECK_DEDUP_SECONDS`. The client is identified by a
  truncated SHA-256 of its IP (unsalted, for de-duplication only); the IP is not stored with the finding.
* Failures are explicit (`analysis_failed`, `persist_failed`); the UI never shows a verdict for a
  failed check.

**Abuse limits** — public scan/check per IP (`SCAN_RATE_PER_MIN`), sweeps per client + global concurrency.

**Secrets** — keys are server-side environment variables only; `/api/readiness` reports booleans and
counts, never values; the extension and PWA contain no keys; `.env` is git- and docker-ignored.

**Client-side data** — the service worker caches only public API responses; private portal data
(investigations, reports, AI output, audit) is not cached and is cleared from storage on logout.

**Fail-closed trust** — scorer, registry or verification errors produce WARNING, never SAFE; an
invalid registry file on hot reload authenticates nothing (`registry_error` in readiness); registry
approval never overrides confirmed malicious evidence (FAKE + manual review) and the Guard never
auto-blocks a registry domain;
the extension shows NOT CHECKED (grey) on any failure; the offline tier cannot emit SAFE.

**Container** — non-root user, app port not published, data in a named volume, healthcheck.

## Known limitations (not solved)

| Area | Limitation | Mitigation / next step |
|---|---|---|
| Identity | No MFA, no SSO, no password-reset email | add OIDC/SSO (e.g. police IdP) before real use |
| Scale | SQLite + in-process rate limiters/sweep threads → single instance only | Postgres + Redis for multi-instance |
| Rate limits | in-memory, reset on restart; per-IP limits depend on correct proxy headers | keep the app behind Caddy only |
| Dependencies | no vulnerability scan was run (offline environment) | run `pip-audit` / Dependabot in CI |
| Real FastAPI | tests ran on a FastAPI-compatible harness because FastAPI could not be installed offline | run `make check` with real dependencies before release |
| Penetration testing | none performed | external review before any production use |
| Data protection | no retention/deletion policy, no at-rest encryption beyond the host disk | define retention with the data owner; encrypt the volume |
| Evidence | screenshots/page text may contain personal data from scam pages | restrict access; retention policy |
| Registry | trust depends on human approvals in a YAML file; integrity relies on git review | signed commits, two-person review |
| AI | external LLM providers receive grounded, zero-PII evidence when keys are set | keep keys unset if data must stay on-prem |
| Checker storage | anyone can submit checks, so the findings table can be filled with junk within the rate limit; redaction is pattern-based and can miss unusual formats (e.g. names, addresses) | add CAPTCHA / per-day quotas; retention policy; review before acting |
| Branding | not authorised by Abu Dhabi Police | no police branding in public deployments without authorisation |

Report security issues privately to the project maintainers.
