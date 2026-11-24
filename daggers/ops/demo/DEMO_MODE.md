# Daggers · DEMO_MODE — one page, no surprises

**What it is:** the exact same app, reading frozen evidence from `web/fixtures/` and `web/evidence/`
instead of the backend. Nothing about the UI changes; the banner says DEMO so nobody is misled.

**How it's turned on (three ways, all equal):**
1. URL — `?mode=demo` (survives reloads while the tab is open)
2. The LIVE/DEMO chip in the topbar (the demo presenter's switch)
3. Backend — `DEMO_MODE=1`; `/api/status` then reports `mode: "demo"` and the app follows

It is also the *automatic* fallback: if the API is unreachable on first boot, `api.js`
marks the session `saved`, keeps the same screens, and says so in the banner. That is the
ladder: **live → last-good cache → fixtures**. There is no state where the screens go blank.

**What changes in DEMO**

| Area | Live | DEMO |
|---|---|---|
| Data source | `/api/*` | `web/fixtures/*.json` (same C0–C4 shapes) |
| Timestamps | from the DB | re-anchored to "minutes ago" at load (`age_min`) |
| Radar stream | SSE `/api/stream` | one scripted finding at ~14 s (sessionStorage guard: once per session) |
| AI Analysis | Gemini → Groq streaming | the stored case, streamed char-by-char, always `provider: "template"` |
| Filing / advancing reports | POST to API | localStorage (the portal still updates live on screen) |
| Guard counters | `/api/guard/stats` | last saved counter (1,243 blocked) |

**What never changes:** every string, both languages, the evidence images, the verdicts.
The demo is not a mock-up of the product — it is the product with its evidence frozen.

**Freeze procedure:** `bash ops/demo/snapshot.sh` → copies `web/fixtures` + `web/evidence`
into `ops/demo/snapshot-<date>/` and stamps `SNAPSHOT.txt`. Copy that folder to the USB stick
and the second laptop. If the repo is lost, `web/` + the snapshot is the whole show.

**Reset between rehearsals:** DevTools → Application → Clear site data (clears the demo-beat
guard and the localStorage report changes). Or open a private window.
