# Checker accuracy improvements (2026-11-25)

Five improvements, implemented in the order requested. All evidence feeds the existing engine
(`core/scorer.py`) and the ONE central verdict (`channels/trust_policy.decide`), so the Checker, the
Police Portal, the extension, Sweep and Guard keep consuming the same backend verdict.

New package: `backend/app/intel/` — `psl.py`, `hostname.py`, `rdap.py`, `probe.py`, `content.py`,
`feeds.py`, `evidence.py`, `providers.yaml`.

## 1. Domain registration age (RDAP) — `intel/rdap.py`

* Only the **ICANN registrable domain** is sent (`es.adpolice.gov.ae/x?y` → `adpolice.gov.ae`), only to
  the RDAP server IANA lists for the TLD (bootstrap `data.iana.org/rdap/dns.json`, cached 30 days).
* Only the RDAP **`registration`** event counts. `last changed`, `expiration`, certificate age and DNS
  age are never used. Recorded: domain, registration date, age in days, source (RDAP server), checked
  time, lookup status (`ok`, `not_found`, `no_rdap_service`, `no_registration_event`, `unavailable`,
  `not_applicable`, `disabled`).
* Any failure = **age unknown** (never "new", never "safe").
* A tenant of a shared platform (`shop.github.io`) or an IP gets `not_applicable`: the provider's age
  is never inherited.
* Effect on the verdict: a domain younger than 30 days adds `infra.domain_recently_registered` (+0.15)
  **only when another signal is present**. An old domain adds nothing: it never earns SAFE and never
  cancels a fraud signal.
* Fixed bug: radar enrichment used the registration date as the *certificate* age when no certificate
  date was available. Certificate age now comes from the certificate only.

## 2. URL and identity — `intel/psl.py`, `intel/hostname.py`, `intel/probe.py`

* **Maintained Public Suffix List** (full algorithm: wildcards, exceptions, ICANN + PRIVATE). The engine
  now uses it for registrable domains (it used tldextract or a small built-in table). The list is
  refreshed by `make reputation-update` / auto-update.
* **Strict host checks**: encoded IPs (`2130706433`, `0x7f000001`, `0177.0.0.1`), percent-encoded hosts,
  invisible / zero-width characters.
* **Deceptive sub-domains and look-alikes of registry organisations** (the brand catalogue was already
  covered): `icp.gov.ae.verify-id.com`, `login.uaepass.ae-verify.com`, `tamm-abudhabi.com`,
  `uaepas.ae`, `dubaipolise.gov.ae.com`, `emiratesnbd-rewards.com`. Common words (police, housing …) are
  not treated as an organisation's name.
* **IDNs are not suspicious by themselves**: `موقع.امارات`, `مثال.مصر`, `例え.jp` produce no signal;
  only confusable mixing (Cyrillic `а` in `аdpolice.gov.ae`) does.
* **Original and final host**: the Checker follows redirects (≤ 5, plus one `meta refresh`). An unknown
  link that lands on a genuine government site is **not** SAFE (`REDIRECT_TO_OFFICIAL_NOT_INHERITED`);
  a SAFE site that sends the visitor to an untrusted host loses SAFE (`REDIRECT_OFF_TRUSTED_SITE`).
* **Secure retrieval** reuses the official fetcher's controls: every hop's DNS checked, private /
  internal / reserved addresses blocked, connection pinned to the checked IP, http/https on default
  ports only, no credentials, size and time limits. A redirect into a private network is blocked and
  reported (`infra.redirect_to_private_network`).

## 3. Content and reputation — `intel/content.py`, `intel/feeds.py`

* **Markup only**: forms, input types, form destinations, meta refresh, script hosts, obfuscation
  markers. No scripts run, no forms submitted, no sub-resources fetched; one plain GET per hop; raw
  HTML is not stored.
* **The decisive combination**: page names a government body + host is not that body's approved
  domain + it collects sign-in / payment / identity data → `content.gov_identity_credential_harvest`
  (0.75, confirmation-level → FAKE).
* **Legitimate sign-in and payment providers** (`intel/providers.yaml`: UAE PASS, Google, Microsoft,
  Apple, PayPal, Stripe, Checkout.com, Amazon Payment Services, N-Genius, Telr, CCAvenue, …): a form
  posting to them is not "data sent to an unrelated destination". This list can never grant SAFE.
* **URL vs host**: feeds now keep exact URLs (`feed_urls` table). Exact URL listed →
  `feeds.phishtank_confirmed` (0.70). Other URLs on the same host listed → `feeds.host_listed` (0.40),
  **not** applied to shared platforms, registry or widely used hosts. The radar poller no longer labels
  a whole shared platform (e.g. all of google.com) because of one Google Forms page.
* **A feed miss is not proof of safety**: the result says "checked — a miss is not proof", "no feed
  data" or "data is N h old"; it never moves a verdict towards SAFE.
* **One observation counts once**: signals carry an evidence group (`form`, `feeds`, `page_identity`,
  `redirect`, `identity_host` …). Only the strongest signal of a group keeps its weight; the others stay
  visible with weight 0 ("counted once").
* **Reputation cutoff raised to the Tranco top 60,000** (`REPUTATION_TOP_N`, was 10,000) so large
  regional sites such as etisalat.ae (#19,589) qualify, under the same guardrails.

## 4. Claim verification — `channels/official/compare.py`, `verify.py`, `lexicon.yaml`

* Every comparison records **authority, jurisdiction, service, amount, effective date** as
  `match / differs / not_stated / not_compared` (`evidence[].attributes`, shown as chips).
* A claim about a **named authority** is verified only by that authority (or a record naming it). Another
  responsible authority's record can still **contradict** it or create a conflict, but cannot verify it.
* **Jurisdiction**: a Dubai claim is not verified by an Abu Dhabi source (federal sources apply to all).
* **Effective date**: when the claim states a date, a source stating a different date is not
  verification ("effective date not confirmed").
* **Classes**: new `legal` category; regulated = legal, fees, benefits (financial_aid), services
  (immigration, traffic), giveaways → need fresh Class A evidence. Class B confirms publication of an
  announcement. Class C is supporting context only (unchanged).
* What was checked / not checked / which evidence decided is recorded in `gov_verification` and in the
  `claim_verification` evidence record (`checked`, `not_checked`, `decided_by`).

## 5. Explainable and consistent

* **`reason_codes`** (one per `trust_reasons` entry; texts unchanged): e.g. `AUTH_GOV_APPROVED`,
  `REPUTATION_WIDELY_USED`, `AUTH_UNLISTED`, `ENGINE_MALICIOUS`, `REDIRECT_OFF_TRUSTED_SITE`,
  `CLAIM_CONTRADICTED`, `NO_SIGNALS_NOT_PROOF`. Full table: `trust_policy.REASON_CODES`.
* **`evidence`**: one record per source (`registry`, `reputation`, `domain_age`, `page`, `feeds`,
  `claim_verification`) with status, checked time and data freshness. **`live_evidence`**: domain age,
  page facts and redirect hops. **`final_domain_auth`**: authentication of the landing host.
  All fields are additive.
* **Same verdict everywhere**: the Checker stores what it shows; the Portal reads the stored record;
  `/api/scan` (extension) and Sweep run the same engine + policy (offline host checks included, no live
  outbound calls per search result); Guard blocks only `blockable` findings and never a registry or
  widely used domain.
* **Extension never green on failure or unknown**: unchanged rule, now with a test covering errors,
  unknown tags and SAFE without proof; failed requests are no longer cached.
* **Privacy**: RDAP gets only the registrable domain; the page probe sends one GET to the link with a
  generic User-Agent and no cookies, Referer or authorisation (tracking parameters and fragments are
  removed first); feed lookups are local; the extension sends no query strings, fragments or cookies.

## 6. Fewer false positives on genuine sites (2026-11-25)

* **A company's name inside another domain is caution, not fraud.** `noon-chi.com` was FAKE only
  because the engine found "noon" (noon.com) in its name — no lure word, no risky TLD, no look-alike
  letters, no page, feed or message evidence. When brand-name matches are the ONLY evidence, the
  verdict is now capped at SUSPICIOUS → **WARNING** ("uses the name noon but is not noon.com").
  Not capped (stays FAKE when the score says so): government names (`adpolice-gov.ae`), lure words in
  the name (`noon-login-verify.com`, `mashreq-update-account.com`), risky TLDs (`adcb-secure-login.xyz`),
  look-alike letters, `@` tricks, deceptive sub-domains, and any page / feed / message evidence.
  (`core/scorer.py`: `name_only_cap`, `host_has_lure`.)
* **Older public websites**: when RDAP knows the registration date and the domain is over a year old,
  the result says "established domain — context only, not proof of safety". Age still never makes a
  site SAFE (rule 1): widely used sites become SAFE through the Tranco top 60,000, and genuine
  organisations through the registry (e.g. `42abudhabi.ae`, class P, pending approval).
* `.ae` domains have no RDAP service at IANA, so their age is always "unknown" (see Limitations).

## 7. Independent Checker, its own result store, no hard-coded lists (2026-11-25)

**Independent of the Police Portal.** The Checker analyses with its own engine and evidence, then
SENDS the result to the Portal (write only). It never reads Portal findings, cases, reports, officer
data or Portal evidence links: the old duplicate check (which read Portal findings), the read-back after
saving and the Portal evidence lookup were removed from the Checker path. Test
`test_checker_independent.py` blocks every Portal read and the Checker still works. (The only shared
data it reads is the external threat-feed list downloaded by the radar — not Portal records.)

**Its own result store** (`backend/app/checker_store/`, separate file `CHECKER_STORE_PATH`, default
`backend/data/checker-store.db`). When the same input (normalised) is checked again, the stored result
is returned directly — no new analysis, nothing sent again (`duplicate: true`, `cached: true`,
`cached_at`; the result page says "Stored result"). A stored result is reused only while valid:
* its key includes the engine, policy, registry and reputation-list versions — approving or revoking a
  registry entry, or installing a new ranking list, makes it miss automatically;
* it expires after `CHECK_CACHE_TTL_S` (6 h), or `CHECK_CACHE_PARTIAL_TTL_S` (10 min) when a source
  (domain age, page, feeds, ranking list) could not be checked, so outages are retried soon;
* `CHECK_CACHE_TTL_S=0` turns reuse off. A failed send to the Portal is never stored.
The Portal still reconciles its own stored findings when the registry changes.

**No hard-coded lists in code.** Everything that is a list of names, domains, words or places is data:
| Data file | Contents |
|---|---|
| `core/rules.yaml` | risky TLDs, giveaway words, common (generic) words, government zones, look-alike letters, fallback suffixes, form-field patterns |
| `channels/official/lexicon.yaml` | claim categories, concepts, **places → jurisdictions** |
| `channels/official/registry.yaml` | approved organisations and their domains (human-approved) |
| `channels/reputation_data/shared_hosts.yaml`, `public_suffix_list.dat` | shared platforms, suffix rules |
| `intel/providers.yaml` | legitimate sign-in and payment providers |
| `core/brands.yaml`, `core/lures.yaml` | brand catalogue, lure words |
`make approve-verified` no longer contains a list of entry IDs: the new CLI command
`approve-verified` approves every pending entry whose own `provenance` records a completed verification
("verified <date>: …"); entries marked "partially checked" stay pending. No verdict is hard-coded
anywhere: every verdict comes from the engine + central policy applied to the evidence.
Remaining in code by nature: signal weights/thresholds (the engine's scoring), reason-code mapping (an
API contract), and the extension's Google results-page selectors (page structure, not trust data).

## 8. Fixes from field reports (2026-11-25)

* **Lure words match whole words.** `…/unlimited-ksa-roaming.html` on eand.ae was flagged for the lure
  "limited" inside "unlimited". A lure must now start at a word boundary (`secure-login`, `/verify`,
  `securelogin` still match); lures shorter than 5 letters must also end at one (`free-gift` matches,
  `freedom` does not).
* **etisalat UAE** (eand.ae, etisalat.ae, eand.com) added to the registry as class P, pending approval.
* **A pending company / news entry no longer blocks the popularity path.** "Pending" means "not reviewed
  yet": a pending class P/C site that is in the Tranco top 60,000 is SAFE as a widely used site
  (government entries, revoked and expired entries stay registry-only).
* **`make trust-status`** shows what the Checker can use on this machine: which registry entries are
  approved and whether the ranking list is loaded. A genuine site that is not SAFE is almost always
  (a) a registry entry still pending → `make approve-verified`, or (b) no ranking
  list → `make reputation-update` (needs internet).

## 9. Established websites — domain age used with other evidence (2026-11-25)

Genuine sites that are neither in the registry nor in the worldwide top 60,000 (e.g. 42abudhabi.ae,
eand.ae) were WARNING. New SAFE path **ESTABLISHED_SITE** ("established website — not a government
source"), decided by `channels/established.py`; thresholds are data (`core/rules.yaml` →
`established_site`). SAFE only when **all** hold:

1. **Age** — RDAP registration ≥ 2 years, or, only where the registry publishes no registration date
   (`.ae` has no RDAP service), **HTTPS in use ≥ 3 years** from public Certificate Transparency logs
   (`intel/ct.py`, Cert Spotter; registrable domain only; reported as "in use since", never as
   registration age). A known YOUNG registration always wins over an old certificate history (a
   re-registered expired domain keeps the old certificates).
2. **Live HTTPS page** retrieved on the same site (no redirect to another site).
3. **No threat-feed listing** for the URL or the host.
4. **No warning sign at all** (only purely structural ones listed in `allowed_signals`, e.g. a deep path).
5. Not a government zone, not a government registry organisation, not a shared platform. A pending
   company / news registry entry does not block it.

The decision is rebuilt from the stored evidence when the Portal re-evaluates findings, so it does not
flip on registry changes. What is shown: "Established: registration (RDAP): 8 year(s), since …" or why
not ("domain age unknown", "the page is not served over HTTPS", "warning signs were found" …).

Checked on 2026-11-25 (read-only): 42abudhabi.ae and the eand.ae roaming page have no password / code /
card / ID fields and name no government body; `apply.42abudhabi.ae` (linked from the homepage) was
added to the 42 Abu Dhabi entry.

**Stale stored results fixed.** The Checker store is now keyed by a build fingerprint (hash of all code,
rules and registry files) and is cleared automatically when it changes; engine 3.1, policy 2.2.
`make reset-checker-store` clears it by hand; `make reset-local-data CONFIRM=yes` wipes all local data
(Portal findings, users, store, evidence) for a clean start.

## 10. Diagnosing "everything is WARNING" (2026-11-25)

Two causes account for genuine sites showing WARNING; neither is a verdict bug:
1. **Registry entries are pending.** Government sites are SAFE only after a named reviewer approves
   them (scope requirement). Until then every government site is WARNING by design.
2. **Live lookups cannot run on the machine** (no internet / proxy), so domain age, certificate
   history, the page and the ranking list are all "unknown", and SAFE through the ranking or
   established-website paths is impossible (fail closed).

Commands:
* `make setup-trust` (no name needed: entries are recorded only as approved, with the date) — one step: approve every verified registry entry, download
  the ranking list, clear stored Checker results, run the doctor. Restart the server afterwards.
* `make doctor` — checks approvals, the ranking list, DNS and internet access to RDAP, certificate
  history, the ranking list, the suffix list and a real page (through the Checker's secure retrieval).
* `make why URL="https://…"` — runs the Checker's analysis for one input on this machine and prints the
  verdict, every reason with its code, every warning sign, every evidence source's status, and what to
  do. Nothing is stored or sent to the Portal.
Note: the secure page retrieval connects directly (pinned to the checked IP address); on a network
that only allows outbound traffic through a proxy, `make doctor` shows it as FAIL.

## 11. Brand catalogue fix (ADCB) and Checker history restore (2026-11-25)

**ADCB showed FAKE.** The engine's brand catalogue (`core/brands.yaml`, from WS1) listed only
`adcb.ae` for ADCB, but the bank's own site is **www.adcb.com** — so the real bank looked like an
impersonation of itself. Root cause: one official domain per brand. The catalogue now accepts
`other_official_domains` (data); a host that is ANY official domain of a brand is never a spoof
(`core/homograph.py`). Verified additions: adcb.com (ADCB), amazon.com (Amazon), eand.ae / eand.com
(etisalat). Unverified domains were NOT added (emiratespost.com is not Emirates Post's — its site is
emiratespost.ae — so it is still flagged). ADCB was also added to the registry (class P, pending →
`make setup-trust`). New test: every catalogue brand's own domain scores UNKNOWN (never flagged).

**Checker history restore.** The Checker page keeps your last 20 checks in this browser
(`localStorage`, exactly what the server returned — personal data in messages already removed). After
closing the browser and/or restarting the program, the last result is shown again (marked "Restored
from your earlier check") and "Your recent checks" lists the others; click one to see its full result.
"Clear history" removes them. Browser test `ops/e2e_restore.mjs` (`make e2e-restore PHASE=1`, restart,
`PHASE=2`): 8/8 passed, with the server stopped and restarted between the phases.

## Settings (`.env`)

| Variable | Default (server) | Meaning |
|---|---|---|
| `CHECK_RDAP_ENABLED` | 1 | RDAP domain age for Checker / investigations |
| `CHECK_PAGE_FETCH_ENABLED` | 1 | secure read-only retrieval of the checked link |
| `CHECK_EVIDENCE_DEADLINE_S` | 10 | total time for live evidence (2–20 s) |
| `REPUTATION_TOP_N` | 60000 | Tranco cutoff for the widely-used-site SAFE path |
| `CHECK_CT_ENABLED` | 1 | certificate-transparency "in use since" (used where RDAP has no date) |
| `CT_API_URL` / `CT_API_KEY` | Cert Spotter / empty | CT search API; a key raises the provider's hourly limit |
| `CHECKER_STORE_PATH` | backend/data/checker-store.db | the Checker's own result store (not the Portal DB) |
| `CHECK_CACHE_TTL_S` | 21600 | reuse a completed result (seconds; 0 = off) |
| `CHECK_CACHE_PARTIAL_TTL_S` | 600 | reuse a result where a source could not be checked |

## Tests

`backend/tests/test_accuracy.py` — 85 tests, offline (fake RDAP servers, web sites and DNS defined in
the file; real PSL and registry). Full backend: **424 passed**. Browser (live server, real Chrome):
reputation 20/20, government 22/22, portal 35/35. Extension: 10/10.

## Limitations

* No internet in the build sandbox: real RDAP servers, real web pages and real feeds were **not**
  contacted here; the live server showed the honest "age unknown / not checked" path. Verify on a
  machine with network.
* **`.ae` domains have no domain age.** Checked 2026-11-25: the IANA RDAP bootstrap
  (`data.iana.org/rdap/dns.json`) has no service for `.ae` (it does for `.abudhabi` and `.dubai`), so
  every `.ae` site — e.g. 42abudhabi.ae — reports `no_rdap_service` / "age unknown". This is honest,
  not a fault, and it does not lower or raise the verdict. (Even with a known age, an old domain never
  earns SAFE: genuine `.ae` organisations become SAFE through the registry, class P.)
* JavaScript-built pages: forms created by scripts are not seen (scripts are never executed).
* The page probe sees what a plain visitor sees; cloaking (different content for scanners) is possible.
* Feed coverage depends on `FEEDS_ENABLED` and the sources configured for the radar.
