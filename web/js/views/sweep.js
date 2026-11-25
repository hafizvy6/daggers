/* Daggers · Sweep — Web/Maps tabs, EN/AR query pills, progressive scoring
   (plan Scenario 4 + 11). Rows light up one by one; bad rows go red with why. */
import { t, reasonsOf } from "../i18n/i18n.js";
import { getSweep, getExamples, tagFor, AuthError, state } from "../api.js";
import { el, tagChip, chip } from "../components/tag.js";
import { pageHead, card, authGate } from "./_shared.js";
import { icons } from "../components/icons.js";
import { emptyState, errorCard } from "../components/empty.js";

export default async function Sweep() {
  const root = el("div");
  root.append(pageHead({
    kicker: t("sweep.kicker"), title: t("sweep.title"), subtitle: t("sweep.subtitle"),
  }));

  let channel = "web";
  let running = false;

  const tabs = el("div", { class: "tabs", role: "tablist" },
    tabBtn("web", "sweep.tabWeb", true), tabBtn("maps", "sweep.tabMaps", false));
  function tabBtn(id, key, sel) {
    const b = el("button", { role: "tab", "aria-selected": String(sel), "data-ch": id, text: t(key) });
    b.addEventListener("click", () => { if (running || channel === id) return; channel = id; paintTabs(); paintQueries(); runBtn.lastChild.textContent = t("sweep.run"); resultsHost.replaceChildren(emptyPanel()); });
    return b;
  }
  function paintTabs() { tabs.querySelectorAll("[role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.ch === channel))); }

  const queryInput = el("input", { class: "input", dir: "auto", type: "text", placeholder: t("sweep.emptyQuery"), "aria-label": t("sweep.queriesTitle") });
  const runBtn = el("button", { class: "btn btn-primary", type: "button" },
    el("span", { html: icons.sweep({ size: 18 }) }), el("span", { text: t("sweep.run") }));
  const pills = el("div", { class: "pill-row" });
  let querySets = { web: [], maps: [] };
  getExamples().then((ex) => {
    querySets = { web: ex.sweep_web || [], maps: ex.sweep_maps || [] };
    paintQueries();
  }).catch(() => { /* offline with no cache: type your own query */ });
  function paintQueries() {
    const list = channel === "maps" ? querySets.maps : querySets.web;
    pills.replaceChildren(...list.map((x) => {
      const p = el("button", { class: "query-pill", type: "button" },
        el("span", { class: "pill-lang", text: x.lang.toUpperCase() }), el("span", { text: x.q }));
      p.addEventListener("click", () => { queryInput.value = x.q; runSweep(x.q); });
      return p;
    }));
  }
  const controls = card(null, "",
    el("div", { class: "stack" },
      el("div", { class: "row", style: "justify-content:space-between" }, tabs,
        el("span", { class: "muted mono", id: "sweepMeta", style: "font-size:var(--fs-xs)" })),
      el("div", { class: "input-row", style: "margin-block-start:var(--s2)" }, queryInput, runBtn),
      pills,
      channel === "maps" ? el("div", { class: "note note-teal", style: "margin-block-start:var(--s2)" },
        el("span", { text: "i" }), el("span", { text: t("sweep.mapsNote") })) : null,
    ));

  const resultsHost = el("div", { class: "stack" });
  const resultsCard = el("div", { class: "card flush" }, resultsHost);

  root.append(controls, el("h2", { style: "margin-block-start:var(--s4)", id: "sweepResultsTitle", text: t("sweep.resultsTitle") }), resultsCard);

  function emptyPanel() {
    return emptyState({
      title: t("sweep.emptyTitle"), body: t("sweep.emptyBody"),
    });
  }
  resultsHost.replaceChildren(emptyPanel());

  async function runSweep(query) {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    runBtn.lastChild.textContent = t("sweep.running");
    let data;
    try {
      data = await getSweep(channel === "maps" ? "maps" : "web", query);
    } catch (err) {
      resultsHost.replaceChildren(err instanceof AuthError
        ? el("div", { class: "stack" }, el("p", { class: "muted", style: "padding:var(--s4)", text: t("sweepx.needLogin") }), authGate(err))
        : errorCard({ title: t("common.errorTitle"), body: err?.message ? t("sweepx.failed", { error: err.message }) : t("common.errorBody") }));
      running = false; runBtn.disabled = false; runBtn.lastChild.textContent = t("sweep.run");
      return;
    }
    if (data.status === "failed") {
      resultsHost.replaceChildren(errorCard({ title: t("common.errorTitle"), body: t("sweepx.failed", { error: data.error || "" }) }));
      running = false; runBtn.disabled = false; runBtn.lastChild.textContent = t("sweep.run");
      return;
    }
    if (query && !data.query) { data.query = query; }
    const meta = document.getElementById("sweepMeta");
    if (meta) meta.textContent = `${t("sweep.engine", { engine: data.engine || "—" })}${data.cached ? " · " + t("sweep.cached") : ""}`;

    const rows = el("div", { class: "sweep-results" });
    resultsHost.replaceChildren(rows);
    if (data.synthetic || data.source_kind === "fixture") {
      resultsHost.prepend(el("div", { class: "note", style: "margin:var(--s3)" }, el("span", { text: "i" }), el("span", { text: t("sweepx.synthetic") })));
    }

    const bad = data.results.filter((r) => tagFor(r) === "fake" || tagFor(r) === "misleading").length;
    const counter = el("div", { class: "card tight", style: "border:0; box-shadow:none; border-block-end:1px solid var(--line-soft); display:flex; gap:var(--s3); align-items:center" },
      el("span", { class: "mono", style: "font-size:var(--fs-xs); color:var(--ink-muted)", text: t("sweep.resultsCount", { n: data.results.length, bad }) }));
    rows.append(counter);

    // Results arrive already scored by the server: render them as they are.
    data.results.forEach((r) => rows.append(buildRow(r, true)));
    running = false;
    runBtn.disabled = false;
    runBtn.lastChild.textContent = t("sweep.run");
    if (bad) {
      rows.append(el("div", { class: "card tight", style: "margin:var(--s4); border-color:var(--tag-fake); background:var(--tag-fake-bg)" },
        el("div", { class: "row" },
          el("span", { class: "tag tag-fake" }, el("span", { class: "tag-dot" }), t("common.tagFake")),
          el("span", { style: "font-weight:600", text: t("sweep.blockedNote") }))));
    }
    resultsCard.after(notSureCard());
  }

  function buildRow(r, scored) {
    const tagKey = tagFor(r);
    const row = el("div", { class: `sweep-row${scored && (tagKey === "fake") ? " is-fake" : scored && tagKey === "misleading" ? " is-mislead" : scored && tagKey === "warning" ? " is-warn" : ""}` });
    const isMaps = channel === "maps" && r.listing;
    row.append(
      el("span", { class: "sr-pos", text: String(r.position ?? "").padStart(2, "0") }),
      el("div", { class: "grow" },
        el("div", { class: "sr-title", text: r.title }),
        el("span", { class: "sr-url", text: isMaps ? `${r.listing.phone}${r.listing.website ? "  ·  " + r.listing.website : ""}` : r.url }),
        el("div", { class: "sr-snippet", text: r.snippet }),
        scored && tagKey !== "safe" && reasonsOf(r).length
          ? el("div", { class: "sr-why", text: t("sweep.whyLine", { reason: reasonsOf(r)[0] }) }) : null,
      ),
      el("div", { class: "sr-tag-cell" },
        scored ? tagChip(tagKey) : el("span", { class: "chip" }, el("span", { class: "chip-k", text: "…" }), el("span", { class: "mono", text: t("sweep.scoring") }))),
    );
    if (scored && r.finding_id && tagKey !== "safe") {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => { location.hash = `#/finding/${r.finding_id}`; });
    }
    return row;
  }

  function notSureCard() {
    const c = card(t("sweep.notSureTitle"), "", el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("sweep.notSureBody") }));
    const a = el("a", { class: "btn btn-ink btn-sm", href: "#/check", style: "margin-block-start:var(--s2)" },
      el("span", { html: icons.check({ size: 16 }) }), document.createTextNode(t("sweep.notSureBtn")));
    c.append(a);
    return c;
  }

  runBtn.addEventListener("click", () => runSweep(queryInput.value.trim()));
  queryInput.addEventListener("keydown", (e) => { if (e.key === "Enter") runSweep(queryInput.value.trim()); });

  // first impression: run the hero query immediately (demo beat 6)
  setTimeout(() => runSweep(), 500);
  return root;
}
