# Daggers · UI-KIT (WS3 owns — read before you touch a pixel)

The design system is **Neo-Outline Soft**: neo-brutalist skeleton (2px ink outlines, hard
offset shadows, mono labels), softened into something a bank or the police can put in front of
the public. Warm paper, calm teal, four honest tags. Light only — it survives a bad projector.

**Two files matter:** `web/css/tokens.css` (all values) and `web/js/i18n/en.json` + `ar.json`
(all words). Everything else composes them.

---

## 1. Tokens — the whole palette

| Token | Value | Use |
|---|---|---|
| `--paper` | `#FAF7F1` | page canvas (dot-grid on top) |
| `--surface` | `#FFFFFF` | cards |
| `--ink` | `#26262E` | text + every outline |
| `--ink-muted` | `#6B6B78` | secondary text (4.9:1 on paper) |
| `--line-soft` | `#E7E1D7` | dividers, dashed borders |
| `--accent` / `--accent-tint` / `--accent-deep` | `#0F766E` / `#E3F1EF` / `#0B5A54` | primary actions, focus, AI panel |
| `--tag-safe` / `-bg` / `-ink` | `#2F9E68` / `#E4F4EB` / `#1F7A4C` | 🟢 SAFE |
| `--tag-warn` … | `#D8921F` / `#FBF0DA` / `#8A5A0B` | 🟡 WARNING |
| `--tag-mislead` … | `#D96F32` / `#FBE9DC` / `#A34A16` | 🟠 MISLEADING |
| `--tag-fake` … | `#D64545` / `#FBE5E5` / `#A62B2B` | 🔴 FAKE |
| `--butter*` | `#F6C445` / `#FCF3D7` / `#6B4C05` | offline / error banners |

**The tag rule (do not break it):** base hues paint *dots, bars, 4px rules* (non-text, ≥3:1).
Tag **text** always uses the `-ink` variant so small mono type clears 4.5:1 on its tint.
`#2F9E68` on `#E4F4EB` is 2.97:1 — fine for a dot, illegal for a word.

**Structure:** `--border: 2px solid var(--ink)` · `--radius: 4px` ·
`--shadow: 3px 3px 0 rgba(38,38,46,.12)` · `--shadow-lift: 5px 5px 0 …` · `--dur: 160ms ease-out`.
Space scale `--s1…--s7` = 4·8·12·16·24·32·48.

## 2. Components (all in `components.css`)

`.card` (outlined paper card) · `.btn` (`-primary -ink -danger -ghost -sm -lg -block`) ·
`.tag` (`-safe -warning -misleading -fake -unknown`, sizes default/`lg`/`xl`) · `.dot-tag` ·
`.chip` / `.chip-reason` (mono data pills) · `.field` + `.input/.textarea` ·
`.seg` + `.lang-switch` (two-state toggles) · `.table` + `.portal-table` · `.stepper`
(`.is-compact` for dense tables) · `.score-bar` · `.breakdown` · `.feed-row` · `.sweep-row` ·
`.evidence-frame` · `.kv` · `.timeline` · `.note`/`.banner` · `.toast` · `.empty` ·
`.sk-*` skeletons · `.tabs` · `.query-pill` · `.stat`.

**Interaction grammar:** cards *paper-lift* on hover (`translate(-2px,-2px)` + bigger shadow);
buttons *press into* the shadow on `:active`; the AI case-writer is the **only** show animation.
Everything respects `prefers-reduced-motion`.

**Forbidden:** dark mode · neon glow · blurred shadows · pure black · gradients on data ·
fear imagery · full-screen red · emoji as UI chrome · raw hex outside `tokens.css`.

## 3. Layout

App shell: topbar (60px) / nav rail (224px ≥1000px, drawer below) / main (max 1180px).
Grid helpers: `.grid-2 .grid-3 .split .stack .row .portal-split`.
**Logical properties only:** `margin-inline-*`, `padding-inline-*`, `inset-inline-*`,
`border-inline-*`, `text-align: start`. `left/right` is a build failure (`ops/check_i18n.py`).

## 4. Type

IBM Plex Sans (EN) · IBM Plex Sans Arabic (AR) · IBM Plex Mono (domains, scores, labels).
Self-hosted `woff2` in `web/fonts/` — **no CDN, ever** (venue Wi-Fi cannot be trusted).
`html[lang="ar"]` switches the stack, body `line-height: 1.75` (EN 1.55), headings 1.35,
`letter-spacing: 0`, no italics.

| Size | Use |
|---|---|
| `--fs-3xl` 44px | hero tag (verdict page) |
| `--fs-2xl` 32px | the big score number |
| `--fs-xl` 24px | screen title (h1) |
| `--fs-lg` 18px | card titles |
| `--fs-md` 15px | body |
| `--fs-sm` 13px | secondary |
| `--fs-xs` 12px | mono labels, chips |

## 5. Bilingual rules (non-negotiable — WS3 §6)

1. `dir` + `lang` are set **once** on `<html>` by `setLang()`. Never per-component.
2. Every visible string is `t("ns.key")` — `ops/check_i18n.py` fails the build otherwise.
3. Numbers, URLs, phones, emails are `dir="ltr"` + `.ltr` (isolated) — **inside Arabic
   sentences too**. Numeral system is Western (1, 2, 3) everywhere.
4. Mirror arrows/back/chevrons only. Never mirror logos, clocks, checks, play, or the
   dagger mark. Score bars grow from `inset-inline-start` (they mirror — that's correct:
   "more" is on the reading-end side).
5. Arabic copy is **written**, not machine-dumped: AI drafts → human reviews → `ar.json`.
   Data-provided strings follow the same rule (`reasons_ar` ships from the data layer).
6. A missing key shows `⟦key⟧` in dev and the English string in prod. Never blank.
7. Test every screen with real Arabic content at 390px before you call it done.

## 6. Accessibility

Text ≥4.5:1 (audit script `ops/check_a11y.mjs` enforces it), focus ring
`3px solid var(--accent)` offset 2px, primary targets ≥44px, one `<h1>` per view,
keyboard walk Feed → Finding → Portal, `aria-live` on the view mount and toasts, `role="img"`
+ label on score bars, `aria-selected` on table rows.

## 7. Data shapes the UI eats

See `daggers-workstream-3-face.md` §3 (C1–C4). Optional additive fields the UI uses and
tolerates the absence of: `brand`, `reasons_ar`, `verdict_note(_ar)`, `signals[]` (score
breakdown), `maps_listing{name,phone,website}`, `age_min`/`cert_age_min`/`filed_age_min`
(demo timestamp re-anchoring). **Never** render a verdict the API didn't send.
