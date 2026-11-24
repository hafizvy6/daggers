# Daggers — Workstream 3: Face & Analyst

**Lane 3 of 3 · SCAMSHIELD AI Hackathon (Abu Dhabi Police × 42 Abu Dhabi)**

Everything the judges see: the PWA, the police portal, the AI Analyst, the design system,
the bilingual catalogs, the demo machinery. The backend in `backend/` is a **demo stand-in**
with the exact C1–C4 contract shapes — when Lane 1 lands the real one, `backend/app/store.py`
is the single file that swaps out.

> **New here?** Open **`START-HERE.md`** first — it has the three commands you actually need.

> **Status:** 8 screens · EN+AR (RTL) · demo story works fully offline · 4 gates + 35 tests green.
> **Zero hardcoded copy, zero hardcoded demo data** — every string is an i18n key, every example
> payload/rule lives in `web/fixtures/*.json`, and all of it is enforced by `ops/check_i18n.py`.

---

## Before anything else (once per machine)

```bash
bash ops/setup.sh        # installs the Python packages (venv if needed) + reports what's missing
```

On **Windows**, work inside **WSL** (`wsl` → `cd /mnt/c/.../daggers`), not PowerShell.
`test_all.sh` checks Python packages, Node and Playwright up front and names anything
missing instead of failing halfway with a traceback.

## Run it (30 seconds, no build step, no node_modules)

```bash
bash ops/dev.sh            # full demo: FastAPI + web, same-origin  → http://localhost:8080
python3 ops/serve_web.py            # static only (Cloudflare Pages parity)   → http://localhost:8000
bash ops/dev.sh demo           # same as api with DEMO_MODE=1 forced
open "http://localhost:8080/?mode=demo#/feed"   # the show, offline, no backend needed
```

Requirements: Python 3.11+ (`fastapi`, `uvicorn`, `httpx`) for the API; nothing at all for `python3 ops/serve_web.py`.
Node is only needed for the two audit scripts (`node ops/check_a11y.mjs http://127.0.0.1:8080`, `node ops/check_offline.mjs http://127.0.0.1:8080`).

**What to look at first**

| Route | What it proves |
|---|---|
| `#/feed` | the radar; in DEMO a brand-new fake slides in after ~14 s with a NEW flag + filing toast |
| `#/finding/42` | side-by-side evidence (official vs clone, circled), reason chips, score breakdown, **File report → "We got you."** |
| `#/portal/7` | the police view: table, stepper, **AI Analysis** (streams EN → one tap → the same case in Arabic), takedown letter |
| `#/guard` | the 60-second switch explainer + blocked counter + honest limits |
| `#/check` · `#/number` | paste a link / message / number → verdict in ~a second, works offline |
| `#/sweep` | Web/Maps tabs, EN/AR hero queries, rows scored one by one before the click |
| `#/verdict/:domain` | the minimal interstitial the Guard serves instead of the scam |

Toggle **EN / ع** in the topbar anywhere — every screen re-renders RTL with handwritten Arabic.

---

## Layout (what's mine)

```
web/
  index.html          shell: topbar · nav · banner · view mount
  config.js           window.API_BASE  ← the only deploy edit
  manifest.json       PWA + share_target (/share → Checker, prefilled)
  sw.js               cache-first shell · network-first /api · SSE passthrough
  fonts/              IBM Plex Sans / Sans Arabic / Mono — self-hosted woff2
  icons/              192 · 512 · maskable  (flat dagger-in-shield)
  evidence/           13 evidence frames (official vs suspect, circled, captioned)
  fixtures/           the demo narrative in C1–C4 shapes (single source)
  css/tokens.css      ★ the entire design system — no raw hex anywhere else
  css/base.css        reset · type · EN/AR line-height contract · focus rings
  css/layout.css      app shell · LOGICAL PROPERTIES ONLY
  css/components.css  cards · tags · buttons · chips · stepper · bars · toasts · skeletons
  js/app.js           hash router · boot · chrome (lang/mode/banner/heartbeat)
  js/api.js           ★ the single swap point: live → last-good cache → fixtures
  js/i18n/            i18n.js · en.json · ar.json   (311 keys × 2, parity-gated)
  js/components/      tag · evidence · toast · empty · skeleton · icons
  js/views/           feed · finding · sweep · check · number · portal · guard · verdict
backend/app/ai/       client.py (Gemini→Groq→template, SSE) · fallback.py · prompts/*.txt
backend/app/api/      ai.py · reports.py          ← the only two routers WS3 owns
backend/app/server.py dev-only demo server (Lane 1's main.py replaces it)
backend/app/store.py  demo store seeded from fixtures — the swap seam for WS1
backend/seed/fixtures only feed.json · reports.json · status.json (the brief's WS3 files)
backend/tests/        test_ai.py · test_contracts.py · test_server.py
ops/                  check_i18n.py · check_a11y.mjs · check_offline.mjs · dev.sh · serve_web.py
ops/demo/             RUNOFSHOW.md · DEMO_MODE.md · snapshot.sh · build_fixtures.py · build_evidence.py
docs/UI-KIT.md        tokens + rules for the other lanes
```

---

## The four things that make this lane work

**1. One swap point.** `js/api.js` is the only module that knows whether it's live, on
last-good cache, or on fixtures. Every view calls the same functions. That's why
`?mode=demo` is a five-minute rehearsal instead of a second app.

**2. The design system is one file.** `tokens.css` holds every color, size, shadow and
motion value. `ops/check_i18n.py` fails the build on a raw hex outside it, a physical
`left/right`, a hardcoded visible string, or an EN/AR key mismatch.

**3. Bilingual is structural, not a translation step.** `dir`/`lang` set once on `<html>`,
logical properties everywhere, LTR islands for domains/numbers, Plex Sans Arabic always,
AR line-height 1.75, letter-spacing 0, no italics. Data-provided text carries its own
`reasons_ar` — the UI never machine-translates.

**4. The AI is bounded by construction.** `POST /api/report/{id}/analysis` reads
`Report.evidence` from the store (never the request body), filters to contract fields
(so a phone number *cannot* reach a provider), and the prompt forbids touching
verdict/score/reasons. Any provider failure — including one that dies mid-stream —
finishes the sentence from the template with `fallback: true`. The badge says **template**
on screen. That's the honesty the pitch claims, enforced in code and tested.

---

## Tests — one command

```bash
bash ops/test_all.sh          # 4 gates + 37 tests, ~2 minutes, ends with ✅ or ❌
```

**Playwright setup — usually nothing to do.** The three browser gates look for Playwright
in this order and use the first one they find:

1. `PLAYWRIGHT_MODULE` if you set it
2. `node_modules/playwright` in this folder — `npm i playwright`
3. **a global install** — `npm i -g playwright` (or Homebrew, or `pip install playwright`)
4. `~/tools/playwright` — the lane's own optional copy

So **if you already have Playwright installed, run the tests and it just works.**
The gates only need the *browser* binary, which one command installs if it's missing:

```bash
npx playwright install chromium     # or: bash ops/setup_browser.sh  (checks first)
```

If something isn't found, the gate says exactly which paths it tried and exits with a
clear message — never a stack trace. Everything except those three gates — the i18n
gate, all 37 Python tests, the syntax check — runs with only Python.

It runs, in order:

| # | Check | What it proves |
|---|---|---|
| 1 | `ops/check_i18n.py` | 311 keys × 2 in exact parity · no literal user-visible text in `web/js` · no demo payloads/URLs/phones baked into JS · no raw hex outside `tokens.css` · logical CSS only · no forbidden files (`main.py`, `config.py`, `Dockerfile`, `Makefile`, …) |
| 2 | `pytest backend/tests` | 12 AI rules (privacy filter, fallback badge, MALICIOUS→"fake"/«مزيّف», priority) · 11 fixture-vs-contract tests · 15 live API tests incl. the SSE stream |
| 3 | `ops/check_syntax.mjs` | all 19 ES modules parse |
| 4 | `ops/check_a11y.mjs` | contrast ≥4.5:1 · 44 px tap targets · RTL · no overflow · full keyboard walk |
| 5 | `ops/check_offline.mjs` | every request same-origin · DEMO story survives with the network unplugged |
| 6 | `ops/check_ui.mjs` | all 8 routes render with 0 console errors · example pills come from fixtures · checker/number verdicts · sweep scores row-by-row · AI stream → AR toggle → takedown · "We got you." toast · EN/AR + RTL |

## Gates (run individually)

```bash
python3 ops/check_i18n.py                       # strings, key parity, no raw hex, logical CSS
node ops/check_a11y.mjs  http://127.0.0.1:8080  # contrast, tap targets, RTL, keyboard, overflow
node ops/check_offline.mjs http://127.0.0.1:8080 # same-origin only + DEMO survives network-off
python3 -m pytest backend/tests -q              # AI rules + contract shapes + live API
```

Last run: **all green** — 311 keys × 2 · i18n clean · a11y clean · purity clean · UI clean · 35/35 tests.

---

## Deploy

1. **Cloudflare Pages** → publish directory `web/`. Free HTTPS → PWA install + share-target work.
2. Edit `web/config.js` → `window.API_BASE = "https://<space>.hf.space"` (Lane 1).
3. Tell Lane 1 the Pages origin for `CORS_ORIGINS`. `api.js` sends `credentials: "omit"`.
4. Register the Space on UptimeRobot (10-min ping) — a cold Space looks like an outage.
5. No `API_BASE` configured? The app honestly runs in DEMO mode off saved evidence.

---

## Definition of Done (WS3 §10) — where we stand

- [x] 8 screens complete, EN + AR, RTL-correct (audited at 1440 & 390 px)
- [x] AI Analysis streams; a dropped stream finishes from the template with a badge
- [x] Zero hardcoded strings (gated)
- [x] Contrast ≥4.5:1 · focus rings · keyboard walk (gated)
- [x] `?mode=demo` full story with the network off, including the radar beat
- [x] PWA manifest + service worker + share-target (`/share` lands in the Checker)
- [x] RUNOFSHOW.md at 5:00 with a fallback line per beat
- [ ] PWA install on a physical Android (needs one real-device pass at the venue)
- [ ] Pages URL + laptop URL cold-start tour (needs the deploy, above)

---

*Daggers · one plan · three lanes · everything joins back to the core.*
