/* Daggers · Sweep — Web/Maps tabs, EN/AR query pills, progressive scoring
   (plan Scenario 4 + 11). Rows light up one by one; bad rows go red with why. */
import { t, reasonsOf } from "../i18n/i18n.js";
import { getSweep, getExamples, tagFor } from "../api.js";
import { el, tagChip, chip } from "../components/tag.js";
import { pageHead, card } from "./_shared.js";
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
  let arbitraryAllowed = false;
  getExamples().then((ex) => {
    querySets = { web: ex.sweep_web || [], maps: ex.sweep_maps || [] };
    arbitraryAllowed = !!ex.sweep_arbitrary;
    queryInput.placeholder = arbitraryAllowed ? t("sweep.emptyQuery") : t("sweep.freeTextOffPlaceholder");
    paintQueries();
  }).catch(() => { queryInput.placeholder = t("sweep.emptyQuery"); });
  function paintQueries() {
    const list = channel === "maps" ? querySets.maps : querySets.web;
    const buttons = list.map((x) => {
      const p = el("button", { class: "query-pill", type: "button" },
        el("span", { class: "pill-lang", text: x.lang.toUpperCase() }), el("span", { text: x.q }));
      p.addEventListener("click", () => { queryInput.value = x.q; runSweep(x.q, x.query_id); });
      return p;
    });
    pills.replaceChildren(...(buttons.length ? buttons : [
      el("span", { class: "muted", style: "font-size:var(--fs-xs)", text: t("sweep.noQueries") }),
    ]));
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
  const afterHost = el("div", { class: "stack" });

  root.append(controls, el("h2", { style: "margin-block-start:var(--s4)", id: "sweepResultsTitle", text: t("sweep.resultsTitle") }), resultsCard, afterHost);

  function emptyPanel() {
    return emptyState({
      title: t("sweep.emptyTitle"), body: t("sweep.emptyBody"),
    });
  }
  resultsHost.replaceChildren(emptyPanel());

  async function runSweep(query, queryId) {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    runBtn.lastChild.textContent = t("sweep.running");
    afterHost.replaceChildren();
    let data;
    try {
      data = await getSweep(channel === "maps" ? "maps" : "web", query, queryId);
    } catch (err) {
      let card_;
      if (err?.status === 403) {
        card_ = emptyState({ title: t("sweep.freeTextOffTitle"), body: t("sweep.freeTextOffBody") });
      } else if (err?.status === 429) {
        card_ = emptyState({ title: t("sweep.rateLimitedTitle"), body: t("sweep.rateLimitedBody") });
      } else if (err?.status === 422) {
        card_ = emptyState({ title: t("sweep.freeTextOffTitle"), body: err.detail || t("sweep.freeTextOffBody") });
      } else {
        card_ = errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") });
      }
      resultsHost.replaceChildren(card_);
      running = false; runBtn.disabled = false; runBtn.lastChild.textContent = t("sweep.run");
      return;
    }
    if (query && !data.query) { data.query = query; }
    const meta = document.getElementById("sweepMeta");
    if (meta) meta.textContent = `${t("sweep.engine", { engine: data.engine || "—" })}${data.cached ? " · " + t("sweep.cached") : ""}`;
    if (!data.results || data.results.length === 0) {
      const body = data.source_kind === "unconfigured" ? t("sweep.unconfiguredBody") : t("sweep.noResultsBody");
      const box = el("div", {}, emptyState({ title: t("sweep.emptyTitle"), body }));
      // Surface the server's own reason — adapter errors carry only type names,
      // never secrets. "duckduckgo: ProviderError" = egress blocked;
      // "duckduckgo: no results" = the provider returned an empty page we could not parse.
      if (Array.isArray(data.errors) && data.errors.length) {
        box.append(el("p", {
          class: "mono ltr",
          style: "font-size:var(--fs-xs); margin:var(--s2) auto 0; max-width:64ch; text-align:center; color:var(--ink-muted); overflow-wrap:anywhere",
          text: data.errors.join(" · "),
        }));
      }
      resultsHost.replaceChildren(box);
      running = false;
      runBtn.disabled = false;
      runBtn.lastChild.textContent = t("sweep.run");
      return;
    }

    const rows = el("div", { class: "sweep-results" });
    resultsHost.replaceChildren(rows);

    const bad = data.results.filter((r) => tagFor(r.verdict) === "fake" || tagFor(r.verdict) === "misleading").length;
    const counter = el("div", { class: "card tight", style: "border:0; box-shadow:none; border-block-end:1px solid var(--line-soft); display:flex; gap:var(--s3); align-items:center" },
      el("span", { class: "mono", style: "font-size:var(--fs-xs); color:var(--ink-muted)", text: t("sweep.resultsCount", { n: data.results.length, bad }) }));
    rows.append(counter);

    // progressive scoring: each row starts neutral, then gets its tag
    const delays = [];
    data.results.forEach((r, i) => {
      const row = buildRow(r, false);
      rows.append(row);
      delays.push(setTimeout(() => {
        row.replaceWith(buildRow(r, true));
      }, 420 + i * 340));
    });

    const last = 420 + data.results.length * 340 + 200;
    setTimeout(() => {
      running = false;
      runBtn.disabled = false;
      runBtn.lastChild.textContent = t("sweep.run");
      // notch: if any fake, show the CTA card at the bottom
      if (bad) {
        const cta = el("div", { class: "card tight", style: "margin:var(--s4); border-color:var(--tag-fake); background:var(--tag-fake-bg)" },
          el("div", { class: "row" },
            el("span", { class: "tag tag-fake" }, el("span", { class: "tag-dot" }), t("common.tagFake")),
            el("span", { style: "font-weight:600", text: t("sweep.blockedNote") })));
        rows.append(cta);
      }
      afterHost.replaceChildren(notSureCard());
    }, last);
  }

  function buildRow(r, scored) {
    const tagKey = tagFor(r.verdict);
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

  // The operator chooses when to call an external provider. No automatic sweep.
  return root;
}
