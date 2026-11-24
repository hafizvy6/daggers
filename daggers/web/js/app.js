/* ============================================================
   Daggers · app.js — hash router + boot + chrome (lang/mode/banner)
   Views are plain ES modules: export default async (ctx) => Node
   ============================================================ */
import { initI18n, setLang, getLang, t, onLangChange } from "./i18n/i18n.js";
import { initApi, watchNetwork, onState, state, setDemo, connectStream, getGuardStats, injectDemoBeat } from "./api.js";
import { icons, logoMark } from "./components/icons.js";
import { el } from "./components/tag.js";
import { toast } from "./components/toast.js";

const ROUTES = {
  feed:    () => import("./views/feed.js"),
  finding: () => import("./views/finding.js"),
  sweep:   () => import("./views/sweep.js"),
  check:   () => import("./views/check.js"),
  number:  () => import("./views/number.js"),
  portal:  () => import("./views/portal.js"),
  guard:   () => import("./views/guard.js"),
  verdict: () => import("./views/verdict.js"),
};

export const app = {
  streamHooks: [],         // views can subscribe to live findings
  lastFinding: null,
};

let currentRoute = null;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "") || "feed";
  const [name, ...rest] = raw.split("/");
  const param = decodeURIComponent(rest.join("/"));
  return { name: ROUTES[name] ? name : "feed", param };
}

function paintIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((n) => {
    const key = n.getAttribute("data-icon");
    if (icons[key] && !n.firstChild) n.innerHTML = icons[key]({ size: 18 });
  });
}

function applyStaticStrings(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((n) => {
    n.textContent = t(n.getAttribute("data-i18n"));
  });
  root.querySelectorAll("[data-i18n-aria]").forEach((n) => {
    n.setAttribute("aria-label", t(n.getAttribute("data-i18n-aria")));
  });
}

/* ---------------- chrome: lang, mode, heartbeat, banner ----------- */
function wireChrome() {
  document.getElementById("brandMark").innerHTML = logoMark({ size: 26 });

  const langSwitch = document.getElementById("langSwitch");
  langSwitch.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-lang]");
    if (b) setLang(b.dataset.lang);
  });

  const modeToggle = document.getElementById("modeToggle");
  modeToggle.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-mode]");
    if (!b) return;
    const demo = b.dataset.mode === "demo";
    setDemo(demo);
    const q = new URLSearchParams(location.search);
    if (demo) q.set("mode", "demo"); else q.delete("mode");
    const qs = q.toString();
    history.replaceState(null, "", `${location.pathname}${qs ? "?" + qs : ""}${location.hash}`);
  });

  // mobile nav drawer
  const nav = document.getElementById("nav");
  const scrim = document.getElementById("navScrim");
  const btn = document.getElementById("menuBtn");
  const closeNav = () => { nav.classList.remove("is-open"); scrim.classList.remove("is-open"); btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", () => {
    const open = !nav.classList.contains("is-open");
    nav.classList.toggle("is-open", open);
    scrim.classList.toggle("is-open", open);
    btn.setAttribute("aria-expanded", String(open));
  });
  scrim.addEventListener("click", closeNav);
  nav.addEventListener("click", (e) => { if (e.target.closest("a")) closeNav(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeNav(); });

  // mode + lang + network → repaint chrome
  onState(renderState);
  onLangChange(() => {
    applyStaticStrings();
    paintLangButtons();
    renderState(state);
    navigate(true);          // every visible string is t() — re-render at the same route
  });
}

function paintLangButtons() {
  document.querySelectorAll("#langSwitch button").forEach((b) => {
    b.setAttribute("aria-pressed", String(b.dataset.lang === getLang()));
  });
}

let lastMode = null;
function renderState(st) {
  // lang buttons
  paintLangButtons();
  // mode chips
  document.querySelectorAll("#modeToggle button").forEach((b) => {
    const demoish = st.demo || st.mode === "demo" || st.mode === "saved";
    b.setAttribute("aria-pressed", String(
      (b.dataset.mode === "demo" && demoish) || (b.dataset.mode === "live" && !demoish)));
  });
  // heartbeat
  const hb = document.getElementById("heartbeat");
  const hbLabel = document.getElementById("hbLabel");
  const down = st.apiDown || st.offline;
  hb.classList.toggle("is-down", down);
  hbLabel.textContent = down ? t("top.down") : t("top.live");
  // banner
  const banner = document.getElementById("banner");
  const tag = document.getElementById("bannerTag");
  const text = document.getElementById("bannerText");
  banner.classList.remove("is-demo");
  if (st.offline) {
    banner.classList.add("is-on"); tag.textContent = "OFFLINE"; text.textContent = t("top.bannerOffline");
  } else if (st.demo || st.mode === "demo") {
    banner.classList.add("is-on", "is-demo"); tag.textContent = "DEMO"; text.textContent = t("top.bannerDemo");
  } else if (st.apiDown) {
    banner.classList.add("is-on"); tag.textContent = "SAVED"; text.textContent = t("top.bannerApi");
  } else {
    banner.classList.remove("is-on");
  }
  // let the router re-render when the mode flips (fixtures ↔ live)
  const sig = `${st.mode}|${st.offline}|${st.apiDown}`;
  if (lastMode !== null && lastMode !== sig) window.dispatchEvent(new CustomEvent("daggers:modechange"));
  lastMode = sig;
}

/* ---------------- router ---------------------------------------- */
export async function navigate(force = false) {
  const { name, param } = parseHash();
  if (!force && currentRoute && currentRoute.name === name && currentRoute.param === param) return;
  const view = document.getElementById("view");
  if (view._cleanup) { try { view._cleanup(); } catch { /* noop */ } view._cleanup = null; }
  currentRoute = { name, param };
  view.setAttribute("data-view", name);

  // nav highlight
  document.querySelectorAll("[data-nav]").forEach((a) => {
    const on = a.dataset.nav === name || (name === "finding" && a.dataset.nav === "feed") || (name === "verdict" && a.dataset.nav === "check");
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });

  try {
    const mod = await ROUTES[name]();
    const ctx = { param, name, app, force };
    const node = await mod.default(ctx);
    // allow views to persist state (SSE hooks etc.) — never leak past route change
    if (view._cleanup) { try { view._cleanup(); } catch { /* noop */ } }
    view._cleanup = node._cleanup || null;
    view.replaceChildren(node);
  } catch (err) {
    console.error("[router]", err);
    view.innerHTML = `<div class="card"><div class="card-title">${t("common.errorTitle")}</div><p>${t("common.errorBody")}</p></div>`;
  }
  if (!location.hash.includes("#/")) return;
  // reset scroll on route change (not on SSE updates)
  if (!sessionStorage.getItem("daggers:keepScroll")) window.scrollTo({ top: 0 });
  sessionStorage.removeItem("daggers:keepScroll");
  paintIcons(view);
  applyStaticStrings(view);
  if (name === "feed" && app.armDemoBeat) app.armDemoBeat();
}

/* ---------------- live stream → views ---------------------------- */
function wireStream() {
  const conn = connectStream({
    onFinding: (finding) => {
      app.lastFinding = finding;
      app.streamHooks.forEach((fn) => { try { fn(finding); } catch (e) { console.error(e); } });
      bumpReportBadge();
      toast(t("top.newCaught"), { kind: "good", tag: t("feed.new"), ms: 6000 });
    },
    onHeartbeat: () => {},
  });
  app.stream = conn;

  // DEMO (offline) radar beat: a new fake lands once per session — beat 4 of the run-of-show.
  // Fires on the first visit to the feed (not wherever the app happened to boot).
  let beatTimer = null;
  const armDemoBeat = () => {
    if (!conn.demo || sessionStorage.getItem("daggers.demoBeat") || beatTimer) return;
    beatTimer = setTimeout(async () => {
      sessionStorage.setItem("daggers.demoBeat", "1");
      try {
        const finding = await injectDemoBeat();
        conn.inject(finding);
        if (location.hash.startsWith("#/feed")) { /* feed hook prepends */ }
      } catch (e) { console.error(e); }
    }, 14000);
  };
  app.armDemoBeat = armDemoBeat;
  if (location.hash.startsWith("#/feed")) armDemoBeat(); // router may not be ready yet — re-armed below too
}

async function bumpReportBadge() {
  try {
    const { getReports } = await import("./api.js");
    const reports = await getReports();
    const badge = document.getElementById("navReportCount");
    if (badge && reports.length) { badge.hidden = false; badge.textContent = String(reports.length); }
  } catch { /* cosmetic */ }
}

/* ---------------- boot ------------------------------------------- */
export async function boot() {
  await initI18n();
  wireChrome();
  await initApi();
  watchNetwork();
  applyStaticStrings();
  paintIcons();
  renderState(state);
  lastMode = `${state.mode}|${state.offline}|${state.apiDown}`;
  await navigate(true);
  wireStream();
  window.addEventListener("hashchange", () => navigate());
  window.addEventListener("daggers:modechange", () => navigate(true));
  bumpReportBadge();

  // share-target landing: /share?url=…&text=…&title=…
  if (/\/(share)\/?$/.test(location.pathname) && !location.hash) {
    const sp = new URLSearchParams(location.search);
    const shared = sp.get("url") || sp.get("text") || sp.get("title") || "";
    sessionStorage.setItem("daggers:share", shared);
    location.replace(`${location.pathname}#/check`);
  } else if (!location.hash) {
    location.replace(`${location.pathname}#/feed`);
  }
}
