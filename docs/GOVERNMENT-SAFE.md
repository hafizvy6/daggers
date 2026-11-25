# Government authentication and SAFE classification (trust policy 2.0)

Date: 2026-11-25 · Policy version `daggers-trust-2.2` · Shipped registry version `reg_a11ab6b2b6620524`

## 1. Why approved government domains were shown as WARNING (root causes)

Traced registry → `Registry.authenticate()` → engine (`core/scorer.py`) → `trust_policy.decide()` → DB → Checker / Portal / extension:

1. **No entry was approved.** Every registry entry was `pending`, so `authenticate()` returned `PENDING` and the policy could never reach SAFE.
2. **Service subdomains were refused.** Entries used `subdomain_policy: exact`, so `www.`, `smartservices.`, `es.`… of a genuine domain came back `UNLISTED` → WARNING.
3. **No non-government SAFE path.** Only class A/B (government) authentication could produce SAFE, so a genuine bank or newspaper could never be SAFE.
4. **The registry was read once at start-up.** Approving an entry had no effect until restart, and the extension Guard kept the old copy.
5. **Stored findings never changed.** A finding saved as WARNING stayed WARNING after approval; the Checker, Portal list and finding page could disagree with the current registry.
6. **Display guards downgraded SAFE.** `web/js/api.js` `tagFor()` and the extension `labelFor()` turned any SAFE that was not government-`authenticated` into WARNING/UNVERIFIED.
7. Three engine gaps found while testing (fixed): name-only heuristics looked at URL signals only (a phishing *message* linking to a genuine domain could be SAFE); the scorer's official allow-list ignored context such as threat-feed hits; giveaway/prize wording with money but no named entity was not flagged on official pages.

## 2. The central verdict (one engine for DB, Checker, Portal, extension)

`backend/app/channels/trust_policy.py::decide()` is the only place a final `tag` is set. Every
caller (`/api/check`, `/api/scan`, radar, investigations, stored-finding reconciliation, Guard) uses it.

| Path | Requires | Result |
|---|---|---|
| **(a) Government SAFE** | exact host or explicitly listed subdomain of an **approved, unexpired** class A/B entry (`AUTHENTICATED`) **and** no suspicious content, no confirmed malicious evidence | **SAFE** — "authenticated official government source", with reviewer, approval date, expiry |
| **(b) Legitimate-site SAFE** | approved class C (independent media → `INDEPENDENT_MEDIA`) or new class P (verified private/commercial organisation → `VERIFIED_ORGANIZATION`) **and** the same independent security checks pass | **SAFE** — "verified website of X — **not** a government source"; never treated as an official source and can never verify a government claim |
| **(b2) Widely used site** (added 2026-11-25, §8) | host **not known to the registry**, its domain ranked in the Tranco top 60,000 (fresh list; raised from 10,000 on 2026-11-25 so large regional sites such as etisalat.ae, #19,589, qualify), not a shared platform, not a government zone, **and zero engine signals** | **SAFE** — "widely used website — not a government source", with worldwide rank and list id |
| Unauthenticated | everything else (unlisted and not reputable, pending, revoked, expired, unlisted subdomain, other port) | engine verdict, never SAFE |

Rules applied in both SAFE paths:
* **Gaps are not evidence.** Missing reputation data, `SOURCE_UNAVAILABLE` / `SOURCE_EXPIRED`, or `NOT_VERIFIABLE` on the site's own claims do not override valid authentication.
* **Authentication never overrides confirmed malicious activity.** Non-name evidence (threat feed, credential/payment harvesting, malicious context) on an approved domain → **FAKE + manual review**, `blockable: false` (the Guard never blocks a registry domain; an officer decides).
* **Suspicious content is still analysed.** OTP/credential requests, giveaway + money wording, or government claims on a genuine page → **WARNING + manual review**.
* **Name heuristics are superseded** for authenticated hosts (a police site naturally contains "police").
* **Impersonation stays FAKE**: look-alike names (`adpolice-gov.ae`), `user@host` tricks, suffix tricks, homographs (Cyrillic `а`), government-brand words on unrelated domains.

## 3. Registry (`backend/app/channels/official/registry.yaml`)

* Classes: **A** authority, **B** official media, **C** independent media, **P** verified private/commercial organisation (new; may not carry `authority_scope` or `source_urls`).
* Every approval keeps `approved_at` (the approval date; a reviewer name is optional and not required), freshness `max_age_days` → `expires_at`, `source`, `provenance`. These are returned in `domain_auth` and shown in the Checker and Portal.
* Host matching: exact registered domain or an **explicitly listed** subdomain only; scheme/port/credentials/case/trailing dot/IDN are normalised first.
* **Hot reload**: the running server re-reads the file when it changes (checked at most every 2 s). An invalid file **fails closed** (no domain authenticated, `registry_error` in `/api/health/ready`) — it never fails open.
* **Reconciliation**: when the registry or policy version changes, stored findings are re-evaluated from their stored evidence, the corrected tag is persisted, and `verdict_history` records the previous tag (last 20 changes). The same finding ID is kept, so Checker, Portal list and finding page always show one verdict.

### Approval is a human step — NOT done in this build

All entries in the shipped registry are **`pending`**. The corrections below are data only (domains,
listed subdomains, provenance evidence). Approving them is your decision — one command, no name needed
(entries are recorded only as `approved` with the date; `make setup-trust` also downloads the ranking list):

```bash
make approve-verified        # approves every pending entry whose provenance records a verification (17 today), then lists the registry
# Docker / another file:  OFFICIAL_REGISTRY_PATH=/data/registry.yaml make approve-verified
```

Until a reviewer approves them, these domains are correctly shown as **WARNING (pending approval)**.
The National stays pending (see §4).

## 4. Domains verified against authoritative sources (2026-11-24)

Verified by fetching the official sites and cross-references (u.ae, Wikipedia, icd.gov.ae, mediaoffice.ae / mediaoffice.abudhabi). The original specification's candidate list was not attached, so the registry's existing candidates were used, plus TAMM and Emirates NBD.

| Entry | Class | Registered domain | Listed subdomains | Evidence (summary) |
|---|---|---|---|---|
| uae-gov-portal | A | u.ae | ask, assets | u.ae titled "The Official Platform of the UAE Government", TDRA; bare domain only (`www.u.ae` not used) |
| uae-pass | A | uaepass.ae | id, docs | linked from u.ae; docs.uaepass.ae: managed by Digital Dubai, TDRA, ADDA; ICP describes UAE Pass |
| abu-dhabi-police | A | adpolice.gov.ae | www, es, srv, ers, aman, cas, ideas, forsa | homepage states it is the official site of Abu Dhabi Police GHQ; .gov.ae restricted zone; subdomains linked from homepage |
| dubai-police | A | dubaipolice.gov.ae | www | canonical URL on dubaipolice.gov.ae (.gov.ae) |
| icp | A | icp.gov.ae | www, smartservices, cc, afkar | titled Federal Authority for Identity, Citizenship, Customs & Port Security |
| mohre | A | mohre.gov.ae | www, ibtikar | MoHRE news on its revamped www.mohre.gov.ae site |
| rta | A | rta.ae | www | RTA copyright footer; Wikipedia. `rta.gov.ae` **not** added (unverified) |
| dewa | A | dewa.gov.ae | www | DEWA copyright footer; Dubai Media Office article |
| tamm | A | tamm.abudhabi | www | linked from adpolice.gov.ae; u.ae Smart Abu Dhabi page; Abu Dhabi Media Office |
| wam | B | wam.ae | www | Emirates News Agency; u.ae links WAM articles |
| abu-dhabi-media-office | B | mediaoffice.abudhabi | www | titled Abu Dhabi Media Office |
| dubai-media-office | B | mediaoffice.ae | www | titled Government of Dubai Media Office |
| khaleej-times | C | khaleejtimes.com | www | footer Galadari Printing and Publishing; Wikipedia |
| gulf-news | C | gulfnews.com | www | footer Al Nisr Publishing; directories |
| emirates-nbd | P | emiratesnbd.com | www, online, businessonline, business, digital, signonline, cdn | titled Emirates NBD; Wikipedia; listed in ICD portfolio |
| 42-abu-dhabi | P | 42abudhabi.ae | www | added 2026-11-25: Abu Dhabi Media Office inauguration article and ADEK programme page point to www.42AbuDhabi.ae; 42 Network campus page lists it. Verified organisation, not government |
| etisalat-uae | P | eand.ae, etisalat.ae, eand.com | www | added 2026-11-25: eand.ae titled "etisalat UAE …", footer "etisalat. All Rights Reserved.", links etisalat.ae and eand.com; Wikipedia: website www.eand.com, ADX: EAND, name reverted from e& to Etisalat in Oct 2026 |
| the-national | C | thenationalnews.com | www | **partially checked — stays pending** (no publisher/independent confirmation) |

Not verified (fetch blocked or no authoritative source): ADCB, `rta.gov.ae`, `www.u.ae`, `www.uaepass.ae`.

## 5. Exact domains tested and results

Backend (`backend/tests/test_gov_safe.py`, 26 tests, a temporary **copy** of the shipped registry approved by "Test Reviewer"):

| Input | Expected → observed |
|---|---|
| any entry while pending (shipped file) | WARNING (PENDING) ✓ |
| u.ae/en, ask.u.ae, uaepass.ae, id.uaepass.ae, www.adpolice.gov.ae/en, adpolice.gov.ae, es.adpolice.gov.ae, www.dubaipolice.gov.ae, icp.gov.ae/en, www.icp.gov.ae, smartservices.icp.gov.ae, www.mohre.gov.ae, ibtikar.mohre.gov.ae, www.rta.ae, www.dewa.gov.ae/en, www.tamm.abudhabi, www.wam.ae/en, www.mediaoffice.abudhabi/en, www.mediaoffice.ae/en | SAFE, AUTHENTICATED, reviewer + expiry present ✓ |
| www.khaleejtimes.com, gulfnews.com, www.emiratesnbd.com/en, online.emiratesnbd.com | SAFE, legitimate_site, **not** authenticated ✓ |
| noon.com (unlisted), www.thenationalnews.com (pending) | WARNING ✓ |
| expired / revoked entry | WARNING (EXPIRED / REVOKED) ✓ |
| evil.adpolice.gov.ae, www.u.ae, evil.emiratesnbd.com, www.adpolice.gov.ae:8443 | not SAFE (unlisted subdomain / port) ✓ |
| www.adpolice.gov.ae@evil.top, adpolice.gov.ae.evil.top, Cyrillic аdpolice.gov.ae, adpolice-gov.ae, abudhabi-police-fines.top, dubaipolice-fines.com, emiratesnbd-rewards.com, adcb-secure-login.xyz | FAKE ✓ |
| HTTPS://WWW.ADPOLICE.GOV.AE/EN, www.adpolice.gov.ae./ (trailing dot), www.adpolice.gov.ae/en?utm_source=x (no scheme) | SAFE (normalised) ✓ |
| message asking for an OTP and linking to the genuine police site | not SAFE ✓ |
| giveaway + "AED 50,000" page text on icp.gov.ae | WARNING + manual review ✓ |
| threat-feed hit on www.mohre.gov.ae | FAKE + manual review, blockable false ✓ |
| registry approved / revoked while running | same finding re-tagged, persisted, history kept, Portal list and dedup return the corrected record ✓ |
| invalid registry file | fails closed (nothing authenticated) ✓ |

Browser (`ops/e2e_government.mjs`, real Chrome, live uvicorn server, registry **copy** approved via the CLI while running — **22/22 passed**): G1 pending → WARNING; G2 approval without restart → same finding SAFE; G3 approval details; G4 history; G5 u.ae/en, smartservices.icp.gov.ae, www.tamm.abudhabi → SAFE; www.emiratesnbd.com/en, www.khaleejtimes.com → SAFE (not official); www.thenationalnews.com, www.u.ae, evil.adpolice.gov.ae → WARNING; adpolice-gov.ae, user@host trick, Cyrillic → FAKE; G6 company/news never called official; G7 OTP message → WARNING; G8 every Portal row equals the Checker; G9 Portal finding page; G10 reload; G11 revocation → WARNING in the Portal; G12 no page errors.

## 6. Modified files

Backend: `channels/official/models.py` (class P, VERIFIED_ORGANIZATION, approval fields, expiry), `channels/official/registry.py` (class P validation, approval details in authentication), `channels/official/extract.py` (C/P never counted as official claims), `channels/official/__init__.py` (policy 2.0), `channels/trust_policy.py` (two SAFE paths, malicious/suspicious overrides, stored-finding adapter), `channels/scoring.py` (all-signal name check, content flags, `retag`), `core/scorer.py` (context on allow-listed domains, government look-alike weight), `main.py` (registry hot reload, fail closed, reconciliation, persistence), `db/repo.py` (stale-policy query, policy update + verdict history), `api/guard.py` (Guard uses the live registry), `checker.py` (precaution for legitimate sites), `config.py` (`OFFICIAL_REGISTRY_PATH`), `channels/official/registry.yaml` (data corrections, all pending).
Frontend: `web/js/api.js` (SAFE accepted for authenticated **or** legitimate site), `web/js/components/analysis.js` (wording, approval details, history card), `web/js/i18n/en.json`, `ar.json`.
Extension: `extension/lib/core.js` (SAFE label for legitimate sites, keeps `legitimate_site`), `extension/tests/core.test.js`.
Tooling/docs: `Makefile` (`approve-verified`, `e2e-gov`, `OFFICIAL_REGISTRY_PATH`), `.env.example`, `docs/*`.
Tests: new `backend/tests/test_gov_safe.py`, new `ops/e2e_government.mjs`; updated `test_api_contracts.py` (new `maliciousness` key) and two scenarios in `ws2/test_official_scenarios.py` whose expectations were the old policy (retrieval failure on an approved domain, class C) — changed deliberately.

## 7. Limitations

* **No entry is approved in the shipped registry** — a named reviewer must run `make approve-verified`. Until then the verified domains show WARNING by design.
* Verification was done by reading public web pages on 2026-11-24, not by an official TDRA/.gov.ae registry API; freshness expiry forces re-review.
* The National, ADCB, `rta.gov.ae` not verified. Other genuine government services are WARNING until added and approved.
* A genuine site outside the Tranco top 60,000 and not in the registry (e.g. a small local shop) stays WARNING; add it to the registry (class P) to make it SAFE. See §8 for the reputation path.
* Official-record retrieval (`registry fetch`) and live claim verification against real sites were not run (no network).
* Tests ran on the FastAPI-compatible harness (real Starlette/Pydantic/uvicorn); re-run `make check`, `make e2e`, `make e2e-gov` with the pinned dependencies.

## 8. Correction (2026-11-25): widely used sites such as YouTube and WhatsApp Web

**What was wrong.** After the first delivery, `https://www.youtube.com/`, `https://web.whatsapp.com/`,
`https://www.google.com/` and `https://github.com/` still came back **WARNING with zero scam
signals**. The only reason was "domain is not in the registry". Path (b) above covered only sites
someone had typed into the registry, which is not what "legitimate private/commercial websites
independently passing security checks" asked for.

**Fix: independent reputation check** (`backend/app/channels/reputation.py`, called from
`ShieldScorer.authenticate()`, decided by the same `trust_policy.decide()`):

1. Used **only** when the registry does not know the host at all (`UNLISTED`). Pending, revoked and
   expired entries and any host of a registry organisation (e.g. `www.u.ae`, `evil.adpolice.gov.ae`)
   are still decided by the registry alone. Government zones (`.gov.ae`, `.mil.ae`, `.abudhabi`,
   `.dubai`, `.gov`, `.mil`) are never SAFE through popularity.
2. The host's domain must be ranked within the top **60,000** (default, `REPUTATION_TOP_N`; was 10,000) of the **Tranco** list
   (https://tranco-list.eu — a research ranking that averages several providers over 30 days and is
   built to resist manipulation). The list must be ≤ 45 days old. It is **data downloaded at run
   time**, not code: nothing is hard-coded and no list ships in the ZIP.
3. The host must not be on a platform where anyone can publish: user sub-domains from the **Public
   Suffix List private section** (github.io, blogspot.com, web.app, … — bundled snapshot of
   2025-12-28, refreshed with the list) and `reputation_data/shared_hosts.yaml` (Google Forms/Sites/
   Drive, link shorteners, file shares, site builders, tunnels). That file can only remove SAFE.
4. The engine must find **no signal at all**: popularity never overrides a look-alike/lexical signal,
   suspicious content, an OTP/payment request, or a threat-feed hit (→ FAKE + manual review; the Guard
   never blocks a whole popular domain).
5. Missing, stale or unreadable list → nothing is SAFE by reputation (fail closed); the reason is
   shown ("reputation list not downloaded yet").

**Getting the list.** The server downloads it automatically at start-up when it is missing or older
than 7 days (`REPUTATION_AUTO_UPDATE=1`, default). Manually: `make reputation-update`. A new list is
picked up without a restart and stored findings are re-tagged (history kept), so the Checker, the
Portal and the extension show the same verdict.

**Tested** (`backend/tests/test_site_reputation.py`, 34 tests, with a TEST ranking file; real PSL):
youtube.com, www/m.youtube.com, web.whatsapp.com, www.whatsapp.com, www.google.com, github.com,
en.wikipedia.org, upper-case/trailing-dot form → SAFE (`REPUTABLE_SITE`, not government);
evil-shop.github.io, promo.blogspot.com, claim-prize.web.app, docs.google.com/forms, sites.google.com,
bit.ly → not SAFE (shared platform); a domain ranked beyond the top N and an unknown site → not SAFE;
www.u.ae, evil.adpolice.gov.ae, moi.gov.ae, pending www.adpolice.gov.ae and www.emiratesnbd.com →
WARNING (registry only); youtube-login-verify.com, `www.youtube.com@evil.top`, youtube.com.evil.top,
Cyrillic yоutube.com → not SAFE; WhatsApp OTP scam message → not SAFE + manual review; threat-feed hit
on youtube.com → FAKE, manual review, not blockable; stale / corrupt / missing list → WARNING; finding
stored as WARNING becomes SAFE when a list is installed (persisted, history, Portal list, dedup);
`/api/scan` agrees; downloader installs a valid list and rejects short lists, bad ids and bad PSL
while keeping the current list. Browser (`ops/e2e_reputation.mjs`, live server, real Chrome):
**19/19 passed**, including the same YouTube finding turning WARNING → SAFE without a restart, the
Portal row and finding page matching the Checker, and falling back to WARNING when the list is
removed. All earlier suites still pass (backend 322, government browser 22/22, portal browser 35/35,
extension 9/9).

**Not verified here:** the real Tranco download (no network in this sandbox — it was exercised with a
fake downloader, and with no network the server correctly marks nothing SAFE by reputation). Tranco
includes Cloudflare Radar data under CC BY-NC 4.0: check the terms before commercial use. The Public
Suffix List is MPL-2.0.

**Files (this correction):** new `backend/app/channels/reputation.py`,
`backend/app/channels/reputation_data/{public_suffix_list.dat,shared_hosts.yaml}`,
`backend/tests/test_site_reputation.py`, `ops/e2e_reputation.mjs`; changed `channels/scoring.py`
(`authenticate()`), `channels/trust_policy.py` (b2 rules, blockable), `channels/official/models.py`
(`REPUTABLE_SITE`, `reputation` field), `channels/official/__init__.py` (policy 2.1), `main.py`
(load / hot reload / auto-download / readiness), `config.py`, `db/repo.py` (`reputation_version`),
`checker.py` (precaution), `web/js/components/analysis.js`, `web/js/i18n/{en,ar}.json`,
`extension/lib/core.js` + test, `backend/tests/test_api_contracts.py`, `Makefile`
(`reputation-update`, `e2e-rep`), `.env.example`, docs.
