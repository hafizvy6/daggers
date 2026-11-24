# Cleanup & test pass — plain words

_24 Nov 2026 · Workstream 3 (Face & Analyst)_

You asked for three things: strip the hardcoded bits, prove we only built our own lane,
and show tests that it still works. Here's what happened, in plain language.

---

## 1. What was "hardcoded" and where it went

**The problem.** Demo data was sprinkled through the JavaScript. Example links, phone
numbers, search queries and the "this looks like a scam because…" rules were literally
typed into the screen code. The takedown letter and the fallback case summary were typed
into Python. That's fine for a demo, but it means the day a real backend arrives you have
to go hunting through the UI to find what to delete — and if a judge asks "where does this
number come from?", the honest answer was "a string on line 74".

**The fix — everything that's *content* now lives in a data file.**

| What | Now lives in |
|---|---|
| Example links, messages and phone numbers behind the pills | `web/fixtures/examples.json` |
| The offline checker's rules (risky endings, lure words, bank names, weights) | `web/fixtures/offline_rules.json` |
| The takedown letter wording, the AI fallback sentences | `backend/app/ai/prompts/fallback_*.txt` |
| Every label, button, sentence in both languages | `web/js/i18n/en.json` · `ar.json` |

The JavaScript now just *reads* those files. Same demo, same screens — but if you want to
change an example link or a rule, you edit a JSON file, not the app.

**The Arabic text.** This was the interesting bug. Regenerating the fixtures quietly wiped
the Arabic versions of the reasons and notes, because they had been added by a one-off
script that lived nowhere. So the Arabic feed silently fell back to English. They're now
built by `ops/demo/build_fixtures.py` itself, so regenerating can never lose them again —
and a test now fails loudly if any finding is missing its Arabic.

---

## 2. Did we stay in our lane?

I checked the folder against §2 of the brief, field by field.

**Absent, as required:** `core/`, `radar/`, `vision/`, `db/`, `guard/`, `channels/`,
`extension/`, `main.py`, `config.py`, `Dockerfile`. Nothing from Lane 1 or Lane 2 exists here.

**Also removed during this pass** (they were ours but out of scope, or leftovers):

- `Makefile` and `backend/run.sh` — extra build entry points nobody asked for
- `backend/app/main.py` → renamed to `server.py` and clearly labelled a **demo stand-in**.
  It is not Lane 1's service; it exists so the screens have something to talk to. It mounts
  only our two routers plus endpoints tagged `demo-standin`.
- `backend/seed/evidence/` — duplicate images; evidence lives in `web/evidence/`
- `backend/seed/fixtures/` trimmed from 24 files to exactly the three the brief lists:
  `feed.json`, `reports.json`, `status.json`
- the `GET /api/report/{id}/why` route — the brief's AI section has no such endpoint

**What the backend actually serves** (checked against the brief's contract list):

- `/api/report/{id}/analysis` — SSE stream, 3-character deltas, final event with both languages ✅
- `/api/report/{id}/takedown` — `{letter_en}` ✅
- `/api/reports` · `/api/reports/{id}` · `/api/reports/{id}/advance` (QUEUED→SUBMITTED→SEEN) ✅
- `/api/sweep` **POST** to create a run, **GET** `/api/sweep/{id}` to fetch it ✅
  (this one was wrong until today: the UI was fetching a sweep without ever creating one.
  It now follows the contract, and two tests lock it down.)

Things that were **not** built because they're not ours: the vision note screen, the Guard
engine, the extension. The prompt file for the vision note exists because the brief lists it;
nothing in the UI references it.

---

## 3. The tests

One command: **`bash ops/test_all.sh`** → finishes with `✅ WS3 — all gates and tests passed`.

It runs six things:

1. **No hardcoded anything** — 311 keys in English and Arabic with exact parity; no literal
   text, URL, `+971` number or hex colour allowed in `web/js`; the forbidden files above
   must not exist.
2. **37 Python tests** — 12 for AI behaviour (never sees a user's name or phone; never
   invents a verdict; always shows the honest "template" badge; MALICIOUS reads as "fake" /
   «مزيّف»), 11 checking every fixture matches the contract shapes in §3 of the brief,
   14 hitting the live API including the streaming endpoint.
3. **Syntax** — all 19 JavaScript modules parse.
4. **Accessibility** — contrast, 44 px tap targets, RTL, keyboard-only walk.
5. **Offline honesty** — every request stays on our own domain; the demo survives the
   network being pulled.
6. **Real browser, 24 checks** — every one of the 8 screens loads with zero console errors;
   the pills come from the fixture file; the checker and number screens return verdicts;
   the sweep scores row by row; the AI streams, switches to Arabic, and drafts a letter with
   no personal data in it; filing shows **"Filed with Abu Dhabi Police. We got you."**;
   switching to Arabic turns the page RTL.

**Three real bugs the tests caught today**, which is the point of writing them:

- Arabic reasons were missing from the regenerated fixtures (found by the contract test).
- The sweep screen never created a run before fetching it (found while checking contracts).
- The portal table had a sixth column that didn't fit, so the header read "BLOCKED TODA"
  (found in a screenshot; the filed-time now sits quietly under the domain).

---

## 4. If you only remember one thing

Nothing on screen is typed into the code anymore. Every sentence is a key, every example is
data, every rule is a file. `bash ops/test_all.sh` proves it — and will fail the moment
anyone slips a literal back in.

---

## 5. Where Playwright lives now (updated after this pass)

Two separate things were tangled together, so they're separated now:

| Thing | Size | Where | Survives a sandbox reset? |
|---|---|---|---|
| The Playwright **module** (the JS) | 12 MB | `~/tools/playwright/` | **Yes** — it's part of the saved workspace |
| The **Chromium binary** | 862 MB | `~/.cache/ms-playwright/` | No — re-downloaded by `bash ops/setup_browser.sh` (~90 MB) |

It used to be in `/tmp/pw`, which survives nothing. That's why the gates would have
failed mysteriously after a reset.

Why the browser can't be committed: the workspace snapshot excludes `.cache/`, and 862 MB
is roughly seven times the snapshot size cap anyway. Committing a browser is the wrong
trade — a 90 MB download once per machine is cheaper and keeps the deliverable folder
small enough to hand over.

**What you actually do now:** nothing, on a machine that already has the browser.
On a fresh one: `bash ops/setup_browser.sh`. The gates find the module by themselves —
there is no environment variable to remember, and `ops/test_all.sh` sets nothing.

### Update — you already have Playwright installed

Then you need to do less, not more. The gates now search, in order: an explicit
`PLAYWRIGHT_MODULE`, a local `node_modules`, **a global install** (`npm i -g playwright`),
then `~/tools/playwright`. A normal install on your laptop is found automatically.

Two clear failure messages replace what used to be a 30-line Playwright banner:

- **exit 2** — no Playwright module anywhere. Lists every path it tried.
- **exit 3** — module found, but Chromium isn't installed. Tells you `npx playwright install chromium`.

Which means on your machine the expected experience is: unzip, run `bash ops/dev.sh`,
run `bash ops/test_all.sh`, see ✅. Nothing to configure.

---

## 6. First-run fixes (after a real machine hit real errors)

Someone ran `bash ops/test_all.sh` on Windows/WSL and got two walls of red. Both were
environment, not code — but the harness should never have got that far silently.

**python packages missing.** Now `test_all.sh` starts with a **preflight** that checks
`fastapi`, `httpx`, `pytest`, `pydantic` and `node` *before* running anything, then prints
one short list of what to install and stops. Exit code 1, no traceback.

**`requirements.txt` was pinned too tightly.** `pydantic==2.10.4` pulls
`pydantic-core==2.27.2`, which has **no cp314 wheel** — so on Python 3.14 (stock in some
WSL/Ubuntu images) `pip install` fails outright. The pins are now lower bounds
(`pydantic>=2.10.4`), which resolve cleanly on 3.10 → 3.14. Verified by asking pip to
resolve the whole file for 3.14.

**`node: command not found`.** Preflight now reports node separately and says how to get
it for WSL/Ubuntu, macOS and Windows. Gate 1 and all 37 Python tests run without node.

**New: `ops/setup.sh`.** One command that installs the Python packages — into `.venv/`
when system pip is blocked by PEP 668 ("externally-managed-environment", very common on
WSL) — then reports on node and Playwright. `test_all.sh` now prefers `.venv/bin/python`
if it exists, so the venv is picked up automatically.

---

## 7. `ERR_ADDRESS_INVALID` & the dev server

The script binds `0.0.0.0` so a phone on the same Wi-Fi can reach the demo — correct for
the venue. But uvicorn prints that bind address as if it were a URL, and Chrome/Edge on
Windows refuse `http://0.0.0.0:8080` outright (`ERR_ADDRESS_INVALID`). Linux `curl`
happily returns 200, which is why this never showed up here.

`ops/dev.sh` now prints a banner with the address a human should actually click —
`http://localhost:8080` — plus a WSL tip and a LAN address for phones. Same fix in
`ops/serve_web.py`.
