# Daggers · Morning-of checklist (WS3 — the face)

**T-60 · health**
- [ ] `curl -s https://<space>.hf.space/api/status` → `mode: live`, heartbeats fresh
- [ ] UptimeRobot ping alive (10-min interval) — the HF Space must not be cold
- [ ] `https://<pages>.pages.dev` loads, banner is **not** showing SAVED
- [ ] `window.API_BASE` on Pages points at the Space; Lane 1 `CORS_ORIGINS` includes the Pages origin
- [ ] `?mode=demo` opens with banner DEMO and 12 findings

**T-45 · the face**
- [ ] Fonts: open each screen on the venue laptop — no system-font flash (self-hosted woff2 checked)
- [ ] EN → AR → EN on Feed, Finding, Portal: no dead clicks, numbers stay Western
- [ ] Evidence images render on Finding + Portal detail (both languages)
- [ ] AI Analysis: live stream, then pull the Wi-Fi mid-stream → TEMPLATE text completes
- [ ] Takedown letter drafts; copy button copies
- [ ] Keyboard: Tab through Feed → a row → Finding → Portal (focus ring visible everywhere)
- [ ] Contrast: `node ops/check_a11y.mjs <url>` → clean
- [ ] Purity: `node ops/check_offline.mjs <url>` → clean (no external requests; demo survives network-off)
- [ ] i18n: `python3 ops/check_i18n.py` → clean (295 keys × 2)

**T-30 · the phone**
- [ ] Daggers installed to home screen (share sheet shows Daggers — share a link from WhatsApp → it lands in Checker)
- [ ] Private DNS set to `daggers-guard.nextdns.io` → **tap “Update now”** in NextDNS
- [ ] Tap a blocked domain in Chrome → block page appears; note the row in Guard stats
- [ ] Number check offline (airplane mode) → still answers
- [ ] Screen brightness up, notch/dynamic island not covering the topbar

**T-15 · the show**
- [ ] `bash ops/demo/snapshot.sh` → copy `ops/demo/snapshot-*` to the USB stick
- [ ] Second laptop: open `?mode=demo`, Wi-Fi **off**, all 8 beats walked once
- [ ] Tabs pre-positioned: ① `#/feed` ② `#/portal` ③ `#/guard`; extension loaded in Chrome
- [ ] `ops/demo/RUNOFSHOW.md` printed or on the phone
- [ ] Clear site data on the show laptop (fresh demo beat), then reload once

**Never on stage:** DevTools, the network tab, an apology. Fallback lines are in RUNOFSHOW §"If…".
