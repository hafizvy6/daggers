# Start here

You unzipped the Daggers **Workstream 3** folder. Three different things you might want:

---

## 0. First time on this machine? Run this once

```bash
bash ops/setup.sh
```

It installs the Python packages (into a `.venv/` if your system Python refuses
system-wide installs — modern Ubuntu/WSL often does), then tells you exactly what's
still missing. Safe to run twice.

> **WSL users — the most common trap:** if you installed Node with the Windows
> installer, `node` inside WSL still says *not found*. They are two separate machines
> that share a disk. Install Node **inside WSL**:
> ```
> curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
> sudo apt-get install -y nodejs
> node --version        # should print v18 or newer
> ```
>
> **Windows:** run everything inside **WSL**, not PowerShell. From `C:\Users\you\Documents\daggers`:
> ```
> wsl
> cd /mnt/c/Users/you/Documents/daggers/daggers
> ```
> `bash`, `node` and `python3` must be reachable from *inside* WSL. If `node` is only
> installed on Windows, `node --version` inside WSL will fail — install it there with
> the command `ops/setup.sh` prints.

## 1. Just look at it (30 seconds, no setup beyond Python)

```bash
python3 ops/serve_web.py
#  →  open http://localhost:8000/?mode=demo#/feed
```

That's the whole show, offline, with no backend at all. Flip **EN / ع** in the top bar to
see the whole thing in Arabic and RTL.

## 2. Run it for real (the demo, with the API)

```bash
bash ops/dev.sh
#  →  open http://localhost:8080
```

> **Never open `http://0.0.0.0:8080`** — if you saw that and got
> `ERR_ADDRESS_INVALID`, that's why. `0.0.0.0` means "listen on every network
> interface"; it is not an address a browser can visit. Use **`localhost`**.
> The script now prints `localhost` for exactly this reason.

Needs `fastapi` + `uvicorn` (`pip install -r backend/requirements.txt`).
Add `bash ops/dev.sh demo` to force DEMO_MODE.

## 3. Prove it works (the tests)

```bash
bash ops/test_all.sh
```

Ends with `✅ WS3 — all gates and tests passed`.

If `bash ops/test_all.sh` stops at **preflight**, it is telling you what is missing —
usually the Python packages (`bash ops/setup.sh`) or Node. It never dumps a traceback.

**You already have Playwright installed, so there is nothing to configure.** The three
browser gates look for it in this order and use the first hit:

1. `PLAYWRIGHT_MODULE` — only if you want to point somewhere specific
2. `node_modules/playwright` in this folder
3. **a global install** — `npm i -g playwright` ← your case
4. `~/tools/playwright` — an optional copy the lane sometimes keeps

The only thing that might still be missing is the Chromium **binary**:

```bash
npx playwright install chromium
```

If a gate can't find something it tells you plainly which paths it tried:

- **exit 2** — no Playwright module found anywhere (it lists every path)
- **exit 3** — module found, but the browser isn't installed (it gives you the command)

The i18n gate, all 37 Python tests and the syntax check need **no browser at all**.

---

## What's in here

| Folder | What it is |
|---|---|
| `web/` | the whole PWA — 8 screens, `tokens.css` design system, EN/AR catalogs, fixtures, self-hosted fonts |
| `backend/` | the AI Analyst (`app/ai/`), the two routers we own (`app/api/`) and `server.py` — a **labelled demo stand-in** with the exact contract shapes |
| `ops/` | `dev.sh` · `serve_web.py` · `test_all.sh` · the four gates · demo build scripts |
| `docs/` | `UI-KIT.md` · `HANDOFF-WS3.md` · `CLEANUP-NOTES.md` (plain-language changelog) |

**Read next:** `README.md` for the full picture, `docs/HANDOFF-WS3.md` for state and known
gaps, `docs/CLEANUP-NOTES.md` for what changed and why in plain words.

## The rules this folder keeps

- Every user-visible word is an i18n key — 311 of them, English and Arabic in exact parity.
- Every demo payload, phone number and heuristic rule is a file in `web/fixtures/`, not code.
- No hex colour outside `web/css/tokens.css`. No external fonts or CDNs. Light mode only.
- The AI reads evidence only, never writes a verdict, and shows an honest **template** badge
  when no model key is set.
- `ops/check_i18n.py` fails the build if literal copy ever creeps back into `web/js`.

---

*Daggers · SCAMSHIELD AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi · Lane 3 of 3*
