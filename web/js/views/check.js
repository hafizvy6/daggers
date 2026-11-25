/* Daggers · Checker — LIVE only.
   A link, a domain, or a suspicious message → POST /api/check → the intelligence
   engine + central verdict policy run on the server → the finding is STORED for
   the Police Portal → the stored finding is displayed here.
   Nothing is decided in the browser and nothing is ever simulated. */
import { t, hasKey } from "../i18n/i18n.js";
import { checkInput, newRequestId, validateInput, CheckError, state, can, tagFor } from "../api.js";
import { el, tagChip } from "../components/tag.js";
import { fmtDateTime } from "../i18n/i18n.js";
import { emptyState } from "../components/empty.js";
import { analysisView } from "../components/analysis.js";
import { pageHead, card } from "./_shared.js";
import { icons } from "../components/icons.js";

const MAX = 4000;

/* ---- Your recent checks, kept in THIS browser so they come back after the browser or the
   program is closed and opened again. What is kept is exactly what the server returned (personal
   data in messages is already removed by the server). Last 20; "Clear history" removes them. */
const HISTORY_KEY = "daggers:checkHistory";
const HISTORY_MAX = 20;
const HISTORY_MAX_BYTES = 2_000_000;

export function loadHistory() {
  try {
    const list = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(list) ? list.filter((h) => h && h.result && typeof h.result === "object") : [];
  } catch { return []; }
}

function saveHistory(list) {
  let items = list.slice(0, HISTORY_MAX);
  try {
    while (items.length && JSON.stringify(items).length > HISTORY_MAX_BYTES) items = items.slice(0, -1);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
  } catch { /* storage unavailable or full: the check itself still worked */ }
  return items;
}

function remember(result) {
  const entry = {
    saved_at: new Date().toISOString(),
    input: String(result.submitted_input || result.normalized_url || result.domain || "").slice(0, 300),
    result,
  };
  const others = loadHistory().filter((h) => !(h.result && h.result.id === result.id && h.input === entry.input));
  return saveHistory([entry, ...others]);
}

function clearHistory() {
  try { localStorage.removeItem(HISTORY_KEY); } catch { /* nothing to clear */ }
}
const STEPS = ["validate", "engine", "verify", "store"];

export default async function Check() {
  const root = el("div");
  root.append(pageHead({ kicker: t("check.kicker"), title: t("check.title"), subtitle: t("check.subtitle") }));

  const wrap = el("div", { class: "stack" });
  root.append(wrap);

  /* share-target landing */
  const shared = sessionStorage.getItem("daggers:share");
  if (shared) {
    sessionStorage.removeItem("daggers:share");
    wrap.append(el("div", { class: "note note-teal" }, el("span", { text: "↪" }),
      el("span", { class: "grow", text: t("check.shareBanner") })));
  }

  /* input */
  const input = el("textarea", {
    id: "checkInput", class: "textarea check-input", dir: "auto", rows: "5", maxlength: String(MAX),
    placeholder: t("check.placeholder"), "aria-describedby": "checkHint checkError",
    autocomplete: "off", spellcheck: "false",
  });
  if (shared) input.value = shared;
  const counter = el("span", { class: "ltr mono", text: `0 / ${MAX}` });
  const hint = el("span", { id: "checkHint", text: t("check.hint") });
  const error = el("p", { id: "checkError", class: "field-error", role: "alert", hidden: true });
  const btn = el("button", { type: "submit", class: "btn btn-primary btn-lg", id: "checkBtn" },
    el("span", { html: icons.check({ size: 20 }) }), el("span", { class: "btn-label", text: t("check.btn") }));
  const clearBtn = el("button", { type: "button", class: "btn btn-ghost", text: t("check.clear") });

  const form = el("form", { class: "stack", style: "gap:var(--s3)", novalidate: true });
  form.append(
    el("div", { class: "field" }, el("label", { for: "checkInput", text: t("check.inputLabel") }), input, error),
    el("div", { class: "check-meta" }, hint, counter),
    el("div", { class: "row" }, btn, clearBtn),
    el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0", text: t("check.privacy") }),
  );
  const result = el("div", { id: "checkResult", "aria-live": "polite" });
  const historyBox = el("div", { id: "checkHistory" });
  wrap.append(card(null, "", form), result, historyBox);

  function renderHistory(list = loadHistory()) {
    if (!list.length) { historyBox.replaceChildren(); return; }
    const items = list.map((h, i) => {
      const b = el("button", { type: "button", class: "history-item", "data-history": String(i),
        style: "display:flex; gap:var(--s2); align-items:center; width:100%; text-align:start; background:none; " +
               "border:0; border-block-end:1px solid var(--border-soft); padding-block:var(--s2); cursor:pointer" },
        tagChip(tagFor(h.result), { size: "sm" }),
        el("span", { class: "grow ltr mono", dir: "auto", style: "overflow:hidden; text-overflow:ellipsis; white-space:nowrap",
          text: h.input || `#${h.result.id}` }),
        el("span", { class: "muted", style: "font-size:var(--fs-xs)", text: fmtDateTime(h.saved_at) }));
      b.addEventListener("click", () => {
        result.replaceChildren(resultView(h.result, { restored: h.saved_at }));
        result.querySelector(".card")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
      return b;
    });
    const clear = el("button", { type: "button", class: "btn btn-ghost btn-sm", id: "clearHistory", text: t("check.historyClear") });
    clear.addEventListener("click", () => {
      clearHistory();
      renderHistory([]);
      result.replaceChildren(emptyState({ title: t("check.emptyTitle"), body: t("check.emptyBody") }));
    });
    historyBox.replaceChildren(card(t("check.historyTitle"), String(list.length),
      el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0", text: t("check.historyNote") }),
      el("div", {}, ...items), clear));
  }

  const previous = loadHistory();
  if (previous.length && !shared) {
    result.append(resultView(previous[0].result, { restored: previous[0].saved_at }));
  } else {
    result.append(emptyState({ title: t("check.emptyTitle"), body: t("check.emptyBody") }));
  }
  renderHistory(previous);

  const updateCount = () => { counter.textContent = `${input.value.length} / ${MAX}`; };
  input.addEventListener("input", () => { updateCount(); showError(null); });
  updateCount();

  function showError(code) {
    if (!code) { error.hidden = true; input.removeAttribute("aria-invalid"); return; }
    error.textContent = hasKey(`check.err_${code}`) ? t(`check.err_${code}`) : t("check.err_generic");
    error.hidden = false;
    input.setAttribute("aria-invalid", "true");
  }

  clearBtn.addEventListener("click", () => {
    input.value = ""; updateCount(); showError(null);
    result.replaceChildren(emptyState({ title: t("check.emptyTitle"), body: t("check.emptyBody") }));
    input.focus();
  });

  let busy = false;
  let requestId = null;
  let lastValue = null;

  async function run(e) {
    e?.preventDefault();
    if (busy) return;                    // double click / Enter spam: one request at a time
    const value = input.value;
    const problem = validateInput(value);
    if (problem) { showError(problem); input.focus(); return; }
    showError(null);
    // One id per distinct submission: re-sending the same text after a network error
    // reuses it, so the backend can never store the same check twice.
    if (value !== lastValue || !requestId) { requestId = newRequestId(); lastValue = value; }

    busy = true;
    btn.disabled = true;
    btn.querySelector(".btn-label").textContent = t("check.checking");
    const progress = progressCard();
    result.replaceChildren(progress.node);
    try {
      const finding = await checkInput(value, requestId);
      progress.done();
      requestId = null;                  // next click on Check it = a new check
      renderHistory(remember(finding));
      result.replaceChildren(resultView(finding));
      result.querySelector(".card")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      progress.stop();
      result.replaceChildren(failureView(err));
      if (err instanceof CheckError && err.status === 422) { showError(err.code); requestId = null; }
    } finally {
      busy = false;
      btn.disabled = false;
      btn.querySelector(".btn-label").textContent = t("check.btn");
    }
  }
  form.addEventListener("submit", run);
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) run(ev);
  });

  function resultView(f, { restored = null } = {}) {
    const node = el("div", { class: "stack" });
    if (restored) {
      node.append(el("div", { class: "note", role: "status", id: "restoredNote" }, el("span", { text: "↺" }),
        el("span", { class: "grow", text: t("check.restoredNote", { at: fmtDateTime(restored) }) })));
    }
    const saved = el("div", { class: "note note-teal", role: "status" },
      el("span", { text: "✓" }),
      el("span", { class: "grow" },
        el("strong", { text: f.duplicate ? t("check.savedDuplicate", { id: f.id }) : t("check.saved", { id: f.id }) }),
        " ", t("check.savedBody")));
    if (can("viewer")) {
      saved.append(el("a", { class: "btn btn-sm", href: `#/finding/${f.id}`, text: t("check.openInPortal") }));
    }
    node.append(saved, analysisView(f), anotherBtn());
    return node;
  }

  function failureView(err) {
    const code = err instanceof CheckError ? err.code : "generic";
    const node = el("div", { class: "stack" });
    node.append(el("section", { class: "card", role: "alert", style: "border-color:var(--tag-warn)" },
      el("div", { class: "card-title" }, el("span", { text: t("check.failTitle") })),
      el("p", { text: hasKey(`check.fail_${code}`) ? t(`check.fail_${code}`) : (err.message || t("check.fail_generic")) }),
      el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("check.failNoVerdict") })));
    if (err instanceof CheckError && err.result) {
      // persist_failed: the analysis exists but was NOT saved — show it, clearly marked.
      node.append(el("div", { class: "note", role: "status" }, el("span", { text: "⚑" }),
        el("span", { text: t("check.notSavedBody") })), analysisView(err.result));
    }
    node.append(anotherBtn(t("check.retry")));
    return node;
  }

  function anotherBtn(text = t("check.another")) {
    const b = el("button", { type: "button", class: "btn", text });
    b.addEventListener("click", () => { input.focus(); input.select(); window.scrollTo({ top: 0, behavior: "smooth" }); });
    return b;
  }

  if (shared) setTimeout(run, 200);
  if (state.offline || state.apiDown) {
    wrap.prepend(el("div", { class: "note" }, el("span", { text: "⊘" }), el("span", { text: t("check.offlineNote") })));
  }
  return root;
}

/* Progress: one HTTP request runs every stage on the server, so the browser cannot
   see individual stages. The card lists what is running and marks the stages done
   only when the stored result has come back — no simulated step-by-step progress. */
function progressCard() {
  const list = el("ol", { class: "progress-steps" });
  const items = STEPS.map((s) => el("li", { class: "is-active", text: t(`check.step_${s}`) }));
  items.forEach((li) => list.append(li));
  const node = el("section", { class: "card", "aria-busy": "true" },
    el("div", { class: "card-title" }, el("span", { text: t("check.progressTitle") })), list);
  return {
    node,
    done() { node.setAttribute("aria-busy", "false"); items.forEach((li) => { li.classList.remove("is-active"); li.classList.add("is-done"); }); },
    stop() { node.setAttribute("aria-busy", "false"); items.forEach((li) => li.classList.remove("is-active")); },
  };
}
