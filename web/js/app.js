/* ============================================================
   Daggers · app.js — hash router + boot + live connection chrome
   Views are plain ES modules: export default async (ctx) => Node
   ============================================================ */
import { initI18n, setLang, getLang, t, onLangChange } from "./i18n/i18n.js";
import { initApi, refreshApi, watchNetwork, onState, state, connectStream, getGuardStats } from "./api.js";
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
  streamHooks: [],         // views subscribe to real SSE findings
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
  root.querySelectorAll("[data-icon]").forEach((node) => {
    const key = node.getAttribute("data-icon");
    if (icons[key] && !node.firstChild) node.innerHTML = icons[key]({ size: 18 });
  });
}

function applyStaticStrings(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.getAttribute("data-i18n"));
  });
  root.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    node.setAttribute("aria-label", t(node.getAttribute("data-i18n-aria")));
  });
}

/* ---------------- chrome: language, connection, banner ----------- */
function wireChrome() {
  document.getElementById("brandMark").innerHTML = logoMark({ size: 26 });

  const langSwitch = document.getElementById("langSwitch");
  langSwitch.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-lang]");
    if (button) setLang(button.dataset.lang);
  });

  // mobile nav drawer
  const nav = document.getElementById("nav");
  const scrim = document.getElementById("navScrim");
  const button = document.getElementById("menuBtn");
  const closeNav = () => {
    nav.classList.remove("is-open");
    scrim.classList.remove("is-open");
    button.setAttribute("aria-expanded", "false");
  };
  button.addEventListener("click", () => {
    const open = !nav.classList.contains("is-open");
    nav.classList.toggle("is-open", open);
    scrim.classList.toggle("is-open", open);
    button.setAttribute("aria-expanded", String(open));
  });
  scrim.addEventListener("click", closeNav);
  nav.addEventListener("click", (event) => { if (event.target.closest("a")) closeNav(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeNav(); });

  onState(renderState);
  onLangChange(() => {
    applyStaticStrings();
    paintLangButtons();
    renderState(state);
    navigate(true);
  });
}

function paintLangButtons() {
  document.querySelectorAll("#langSwitch button").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.lang === getLang()));
  });
}

const RADAR_ADAPTERS = ["crt", "feeds", "enrich", "render", "search", "maps"];

function liveAdapterCount(st) {
  const adapters = st.adapters || {};
  return RADAR_ADAPTERS.filter((name) => adapters[name] && adapters[name].enabled).length;
}

let lastSignature = null;
function renderState(st) {
  paintLangButtons();
  const down = st.apiDown || st.offline;
  const adaptersOn = liveAdapterCount(st);

  const chip = document.getElementById("connectionChip");
  const chipLabel = document.getElementById("connectionLabel");
  if (chip) chip.classList.toggle("is-down", down);
  if (chipLabel) chipLabel.textContent = down ? t("top.down") : t("top.modeLive");

  const heartbeat = document.getElementById("heartbeat");
  const heartbeatLabel = document.getElementById("hbLabel");
  heartbeat.classList.toggle("is-down", down);
  heartbeatLabel.textContent = down ? t("top.down") : t("top.live");

  const banner = document.getElementById("banner");
  const tag = document.getElementById("bannerTag");
  const text = document.getElementById("bannerText");
  banner.classList.remove("is-on");
  if (st.offline) {
    banner.classList.add("is-on");
    tag.textContent = t("top.offlineTag");
    text.textContent = t("top.bannerOffline");
  } else if (st.apiDown) {
    banner.classList.add("is-on");
    tag.textContent = t("top.apiUnavailableTag");
    text.textContent = t("top.bannerApi");
  } else if (adaptersOn === 0) {
    banner.classList.add("is-on");
    tag.textContent = t("top.adaptersTag");
    text.textContent = t("top.bannerAdapters");
  }
  const signature = `${st.mode}|${st.offline}|${st.apiDown}|${adaptersOn}`;
  if (lastSignature !== null && lastSignature !== signature) {
    window.dispatchEvent(new CustomEvent("daggers:modechange"));
  }
  lastSignature = signature;
}

/* ---------------- router ---------------------------------------- */
export async function navigate(force = false) {
  const { name, param } = parseHash();
  if (!force && currentRoute && currentRoute.name === name && currentRoute.param === param) return;
  const view = document.getElementById("view");
  if (view._cleanup) { try { view._cleanup(); } catch { /* noop */ } view._cleanup = null; }
  currentRoute = { name, param };
  view.setAttribute("data-view", name);

  document.querySelectorAll("[data-nav]").forEach((link) => {
    const on = link.dataset.nav === name || (name === "finding" && link.dataset.nav === "feed") || (name === "verdict" && link.dataset.nav === "check");
    if (on) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });

  try {
    const module = await ROUTES[name]();
    const context = { param, name, app, force };
    const node = await module.default(context);
    if (view._cleanup) { try { view._cleanup(); } catch { /* noop */ } }
    view._cleanup = node._cleanup || null;
    view.replaceChildren(node);
  } catch (error) {
    console.error("[router]", error);
    view.innerHTML = `<div class="card"><div class="card-title">${t("common.errorTitle")}</div><p>${t("common.errorBody")}</p></div>`;
  }
  if (!location.hash.includes("#/")) return;
  if (!sessionStorage.getItem("daggers:keepScroll")) window.scrollTo({ top: 0 });
  sessionStorage.removeItem("daggers:keepScroll");
  paintIcons(view);
  applyStaticStrings(view);
}

/* ---------------- live stream → views ---------------------------- */
function wireStream() {
  const connection = connectStream({
    onFinding: (finding) => {
      app.lastFinding = finding;
      app.streamHooks.forEach((fn) => { try { fn(finding); } catch (error) { console.error(error); } });
      bumpReportBadge();
      toast(t("top.newCaught"), { kind: "good", tag: t("feed.new"), ms: 6000 });
    },
    onHeartbeat: (status) => {
      // A real heartbeat is also a successful liveness probe.
      if (status?.mode === "live" && state.apiDown) refreshApi();
    },
  });
  app.stream = connection;
}

async function bumpReportBadge() {
  try {
    const { getReports } = await import("./api.js");
    const reports = await getReports();
    const badge = document.getElementById("navReportCount");
    if (!badge) return;
    if (reports.length) {
      badge.hidden = false;
      badge.textContent = String(reports.length);
    } else {
      badge.hidden = true;
      badge.textContent = "";
    }
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
  lastSignature = `${state.mode}|${state.offline}|${state.apiDown}|${liveAdapterCount(state)}`;
  await navigate(true);
  wireStream();
  window.addEventListener("hashchange", () => navigate());
  window.addEventListener("daggers:modechange", () => navigate(true));
  bumpReportBadge();
  getGuardStats().catch(() => {});

  // share-target landing: /share?url=…&text=…&title=…
  if (/\/(share)\/?$/.test(location.pathname) && !location.hash) {
    const params = new URLSearchParams(location.search);
    const shared = params.get("url") || params.get("text") || params.get("title") || "";
    sessionStorage.setItem("daggers:share", shared);
    location.replace(`${location.pathname}#/check`);
  } else if (!location.hash) {
    location.replace(`${location.pathname}#/feed`);
  }
}
