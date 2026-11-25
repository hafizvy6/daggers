/* ============================================================
   Daggers · i18n runtime — catalogs, t(), setLang(), dir/lang
   Rules (WS3 §6): every visible string is t("ns.key"); missing key
   → key in dev, English in prod; Intl with the active locale;
   Western numerals site-wide.
   ============================================================ */

const LANGS = ["en", "ar"];
const STORAGE_KEY = "daggers.lang";
let catalog = {};
let fallback = {};
let current = "en";
const listeners = new Set();
const isDev = !!(globalThis.__DAGGERS_DEV__ ||
  (location.hostname === "localhost" || location.hostname === "127.0.0.1"));

export const locale = () => (current === "ar" ? "ar-AE" : "en-AE");

async function loadCatalog(lang) {
  const res = await fetch(new URL(`./${lang}.json`, import.meta.url), { cache: "no-cache" });
  if (!res.ok) throw new Error(`catalog ${lang}: ${res.status}`);
  return res.json();
}

export async function initI18n() {
  const saved = localStorage.getItem(STORAGE_KEY);
  const fromUrl = new URLSearchParams(location.search).get("lang");
  const initial = LANGS.includes(fromUrl) ? fromUrl : (LANGS.includes(saved) ? saved : "en");
  const [en, ar] = await Promise.all([loadCatalog("en"), loadCatalog("ar")]);
  fallback = en;
  catalog = { en, ar };
  applyLang(initial, { silent: true });
  return initial;
}

function applyLang(lang, { silent = false } = {}) {
  current = lang;
  const html = document.documentElement;
  html.setAttribute("lang", lang);
  html.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
  localStorage.setItem(STORAGE_KEY, lang);
  document.title = `${t("common.appName")} — ${t("common.appSub")}`;
  if (!silent) listeners.forEach((fn) => fn(lang));
}

export function setLang(lang) {
  if (!LANGS.includes(lang) || lang === current) return;
  applyLang(lang);
  // re-render everything cleanly at the same route
  location.hash = location.hash || "#/feed";
  window.dispatchEvent(new CustomEvent("daggers:lang", { detail: { lang } }));
}

export const getLang = () => current;
export const onLangChange = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };

function lookup(cat, key) {
  let node = cat;
  for (const part of key.split(".")) {
    if (node == null || typeof node !== "object") return undefined;
    node = node[part];
  }
  return typeof node === "string" ? node : undefined;
}

/** True when the key exists in the active (or fallback) catalog. */
export const hasKey = (key) => (lookup(catalog[current], key) ?? lookup(fallback, key)) !== undefined;

/** t("feed.title") or t("feed.count", { n: 3 }) — {var} interpolation. */
export function t(key, vars) {
  let s = lookup(catalog[current], key) ?? lookup(fallback, key);
  if (s === undefined) {
    if (isDev) console.warn("[i18n] missing key:", key);
    return isDev ? `⟦${key}⟧` : (key.split(".").pop() || key);
  }
  if (vars) s = s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? `{${k}}`));
  return s;
}

/**
 * Pick the active-language variant of data-provided text.
 * Contract: WS1 may ship `reasons_ar`, `verdict_note_ar`, `label_ar` — the
 * backend/catalog supplies them; we never machine-translate in the UI.
 */
export function localized(obj, field) {
  if (!obj) return undefined;
  const arKey = `${field}_ar`;
  const pick = current === "ar" ? (obj[arKey] ?? obj[field]) : (obj[field] ?? obj[arKey]);
  return pick;
}
export const reasonsOf = (obj) => localized(obj, "reasons") || obj?.reasons || [];

/** Attach the lang attribute + LTR isolation to raw data (domains, numbers). */
export function ltr(s) {
  const span = document.createElement("span");
  span.className = "ltr";
  span.dir = "ltr";
  span.textContent = s;
  return span;
}

/* ---------- Intl helpers (active locale, Western numerals) --------- */
const nf = (opts = {}) => new Intl.NumberFormat("en-US", { useGrouping: true, ...opts });
export const fmtNum = (n) => nf().format(n ?? 0);
export const fmtPct = (n) => `${nf({ maximumFractionDigits: 0 }).format(n ?? 0)}%`;
export const fmtScore = (s) => (Math.round((s ?? 0) * 100) / 100).toFixed(2);

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "short" });
export function timeAgo(iso, now = Date.now()) {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "";
  const mins = Math.round((now - then) / 60000);
  if (mins < 1) return t("common.justNow");
  if (mins < 60) return t("common.minsAgo", { n: mins });
  const h = Math.round(mins / 60);
  if (h < 24) return t("common.hoursAgo", { n: h });
  return t("common.daysAgo", { n: Math.round(h / 24) });
}

export function fmtDateTime(iso) {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false,
  }).format(d);
}

export function fmtTime(iso) {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false }).format(d);
}
