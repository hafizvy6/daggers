/* Daggers · Portal — the police dashboard (plan Scenario 7).
   Reports table · detail pane · AI Analysis streams EN → AR toggle →
   takedown letter. Evidence-only; no canned cases. */
import { t, fmtNum, fmtDateTime, timeAgo, getLang, reasonsOf } from "../i18n/i18n.js";
import { getReports, advanceReport, streamAnalysis, getTakedown, tagFor, state } from "../api.js";
import { el, tagChip, chip, reasonChip } from "../components/tag.js";
import { evidenceFrame } from "../components/evidence.js";
import { toast } from "../components/toast.js";
import { emptyState, errorCard } from "../components/empty.js";
import { cardsSkeleton } from "../components/skeleton.js";
import { pageHead, card, kv } from "./_shared.js";
import { icons } from "../components/icons.js";

const STATUS_ORDER = ["QUEUED", "SUBMITTED", "SEEN"];

export default async function Portal(ctx) {
  const root = el("div");
  root.append(pageHead({
    kicker: t("portal.kicker"), title: t("portal.title"), subtitle: t("portal.subtitle"),
  }));

  const statsHost = el("div", { class: "stack", style: "gap:var(--s3)" });
  const split = el("div", { class: "portal-split" });
  root.append(statsHost, split);
  const tableHost = el("div", { class: "card flush" }, cardsSkeleton(2));
  const detailHost = el("div", { class: "stack" });
  split.append(tableHost, detailHost);

  let reports = [];
  let selectedId = ctx.param ? Number(ctx.param) : null;

  try {
    reports = await getReports();
  } catch {
    tableHost.replaceChildren(errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") }));
    return root;
  }
  if (!reports.length) {
    tableHost.replaceChildren(emptyState({ title: t("portal.emptyTitle"), body: t("portal.emptyBody") }));
    detailHost.append(emptyState({ title: t("portal.selectTitle"), body: t("portal.selectBody") }));
    return root;
  }
  if (!selectedId || !reports.some((r) => r.id === selectedId)) selectedId = reports[0].id;

  paintStats();
  paintTable();
  paintDetail(reports.find((r) => r.id === selectedId));

  function paintStats() {
    const by = (s) => reports.filter((r) => r.status === s).length;
    const auto = reports.filter((r) => r.auto).length;
    const statCard = (num, label, accent) => el("div", { class: "stat", style: accent ? "border-inline-start:4px solid var(--accent); padding-inline-start:var(--s3)" : "" },
      el("span", { class: "stat-num ltr", text: fmtNum(num) }), el("span", { class: "stat-label", text: label }));
    statsHost.replaceChildren(el("div", { class: "card tight" },
      el("div", { class: "stat-row" },
        statCard(reports.length, t("portal.countReports")),
        statCard(by("QUEUED"), t("portal.countQueued")),
        statCard(by("SUBMITTED"), t("portal.countSubmitted")),
        statCard(by("SEEN"), t("portal.countSeen")),
        statCard(auto, t("portal.countAuto")),
      )));
  }

  function stepper(status, compact = false) {
    const host = el("span", { class: `stepper${compact ? " is-compact" : ""}` });
    STATUS_ORDER.forEach((s, i) => {
      const idx = STATUS_ORDER.indexOf(status);
      const cls = s === status ? "is-current" : i < idx ? "is-done" : "";
      const label = t(`portal.${s.toLowerCase()}`);
      const showText = !compact || cls === "is-current";
      host.append(el("span", {
        class: `step ${cls}`,
        "aria-label": compact ? label : null,
        title: compact ? label : null,
      }, showText ? el("span", { class: "step-label", text: label }) : null));
      if (i < STATUS_ORDER.length - 1) host.append(el("span", { class: `step-line ${i < idx ? "is-done" : ""}` }));
    });
    return host;
  }

  function paintTable() {
    const wrap = el("div", { class: "table-wrap" });
    const table = el("table", { class: "table portal-table" });
    table.append(el("thead", {}, el("tr", {},
      el("th", { text: t("portal.colId") }),
      el("th", { text: t("portal.colDomain") }),
      el("th", { text: t("portal.colTag") }),
      el("th", { text: t("portal.colStatus") }),
      el("th", { text: t("portal.colHits") }),
    )));
    const tbody = el("tbody");
    reports.forEach((r) => {
      const tr = el("tr", { "data-id": r.id, "aria-selected": String(r.id === selectedId), tabindex: "0" });
      tr.append(
        el("td", { class: "mono", text: `#${r.id}` }),
        el("td", { class: "col-domain" },
          el("span", { class: "ltr", text: r.domain || r.evidence?.domain || "—" }),
          r.auto ? el("span", { class: "auto-chip", text: t("portal.auto") }) : null,
          el("span", { class: "cell-sub mono ltr", text: r.filed_at ? timeAgo(r.filed_at) : "—" })),
        el("td", {}, tagChip(tagFor(r.evidence?.verdict || "MALICIOUS", r.evidence))),
        el("td", {}, stepper(r.status, true)),
        el("td", { class: "mono ltr", text: fmtNum(r.blocked_hits ?? 0) }),
      );
      const open = () => {
        selectedId = r.id;
        history.replaceState(null, "", `#/portal/${r.id}`);
        paintTable();
        paintDetail(r);
      };
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      tbody.append(tr);
    });
    table.append(tbody);
    wrap.append(table);
    tableHost.replaceChildren(wrap,
      el("div", { style: "padding:var(--s3) var(--s4); border-block-start:1px solid var(--line-soft); font-size:var(--fs-xs); color:var(--ink-muted)", text: t("portal.zeroPii") }));
  }

  function paintDetail(r) {
    detailHost.replaceChildren();
    if (!r) return;
    const ev = r.evidence || {};
    const tagKey = tagFor(ev.verdict || "MALICIOUS", ev);

    const head = el("section", { class: "card" });
    head.append(
      el("div", { class: "row", style: "justify-content:space-between" },
        el("h2", { style: "margin:0", text: t("portal.detailTitle", { id: r.id }) }),
        tagChip(tagKey, { size: "lg" })),
      el("div", { class: "vh-domain", style: "font-size:var(--fs-md); margin-block:var(--s2)", text: r.domain || ev.domain }),
      el("div", { class: "row", style: "justify-content:space-between" },
        stepper(r.status),
        el("span", { class: "chip" }, el("span", { class: "chip-k", text: t("portal.colHits") }), el("span", { class: "mono ltr", text: fmtNum(r.blocked_hits ?? 0) }))),
      el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block:var(--s2) 0", text: t("portal.hitsNote") }),
    );
    detailHost.append(head);

    // facts
    detailHost.append(card(null, "", kv([
      [t("portal.filedBy"), r.auto ? t("portal.filedByAuto") : t("portal.filedByUser")],
      [t("portal.filedAt"), r.filed_at ? fmtDateTime(r.filed_at) : "—"],
      [t("common.source"), ev.source],
      [t("finding.certAge"), ev.cert_issued ? timeAgo(ev.cert_issued) : "—"],
      [t("feed.colClone"), ev.clone != null ? `${ev.clone}%` : "—"],
    ])));

    // evidence thumbnail
    if (ev.evidence_url || ev.id) {
      detailHost.append(el("div", {},
        el("div", { class: "card-title", style: "font-size:var(--fs-sm)" }, el("span", { text: t("portal.evidenceTitle") })),
        evidenceFrame({ ...ev, evidence_url: ev.evidence_url }, { compact: true })));
    }

    // reasons
    if (ev.reasons?.length) {
      detailHost.append(card(t("finding.reasonsTitle"), t("common.reasons"), el("div", { class: "chips" }, ...reasonsOf(ev).map(reasonChip))));
    }

    // AI panel
    const ai = aiPanel(r, ev);
    detailHost.append(ai.node);

    // advance status
    const adv = el("section", { class: "card" });
    const nextStatus = STATUS_ORDER[STATUS_ORDER.indexOf(r.status) + 1];
    if (nextStatus) {
      const key = nextStatus === "SUBMITTED" ? "portal.advanceSubmitted" : "portal.advanceSeen";
      const b = el("button", { class: "btn btn-block" }, el("span", { html: icons.check({ size: 16 }) }), el("span", { text: t(key) }));
      b.addEventListener("click", async () => {
        b.disabled = true;
        try {
          await advanceReport(r.id, nextStatus);
          r.status = nextStatus;
          paintStats(); paintTable();
          b.replaceWith(el("div", { class: "row" }, el("span", { class: "tag tag-safe" }, el("span", { class: "tag-dot" }), t(`portal.${nextStatus.toLowerCase()}`))));
        } catch {
          b.disabled = false;
          toast(t("portal.advanceErr"), { kind: "bad" });
        }
      });
      adv.append(b);
    } else {
      adv.append(el("div", { class: "row" }, el("span", { class: "tag tag-safe" }, el("span", { class: "tag-dot" }), t("portal.advanceDone"))));
    }
    detailHost.append(adv);
  }

  /* ---------------- AI Analyst panel ----------------------------- */
  function aiPanel(r, ev) {
    const node = el("section", { class: "card ai-panel", style: "border-color: var(--accent)" });
    const badgeHost = el("span");
    const head = el("div", { class: "ai-head" },
      el("div", { class: "card-title", style: "margin:0" },
        el("span", { html: icons.spark({ size: 18 }) }), el("span", { text: t("portal.aiTitle") })),
      badgeHost);
    node.append(head, el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:var(--s1) 0 0", text: t("portal.aiNote") }));

    const out = el("div", { class: "ai-out", dir: "ltr", lang: "en" });
    out.textContent = t("portal.aiEmpty");
    out.style.color = "var(--ink-muted)";

    const langToggle = el("div", { class: "lang-switch is-ai", hidden: true },
      btnLang("en", "portal.aiLenEn"), btnLang("ar", "portal.aiLenAr"));
    function btnLang(code, key) {
      const b = el("button", { type: "button", "data-l": code, "aria-pressed": "true", text: t(key), lang: code });
      return b;
    }

    const runBtn = el("button", { class: "btn btn-primary" },
      el("span", { html: icons.spark({ size: 18 }) }), document.createTextNode(t("portal.aiBtn")));
    const takeBtn = el("button", { class: "btn", disabled: true },
      el("span", { html: icons.doc({ size: 16 }) }), document.createTextNode(t("portal.takedownBtn")));

    const actions = el("div", { class: "ai-actions" }, runBtn, takeBtn, langToggle);
    const takeHost = el("div");
    node.append(out, actions, takeHost);

    const cacheKey = `daggers.ai.${r.id}`;
    const savedAI = (() => { try { return JSON.parse(localStorage.getItem(cacheKey) || "null"); } catch { return null; } })();
    let result = savedAI;

    function paintResult(lang) {
      if (!result) return;
      out.textContent = lang === "ar" ? result.summary_ar : result.summary_en;
      out.dir = lang === "ar" ? "rtl" : "ltr";
      out.lang = lang === "ar" ? "ar" : "en";
      out.style.color = "";
      badgeHost.replaceChildren(
        result.fallback
          ? el("span", { class: "ai-badge is-fallback", text: t("portal.aiFallbackTag") })
          : el("span", { class: "ai-badge", text: result.provider || "AI" }),
        el("span", { class: "muted", style: "font-size:var(--fs-xs); margin-inline-start:var(--s2)", text: t("portal.aiStored") }),
      );
      langToggle.hidden = false;
      langToggle.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.l === lang)));
      takeBtn.disabled = false;
      runBtn.textContent = "";
      runBtn.append(el("span", { html: icons.spark({ size: 18 }) }), document.createTextNode(t("portal.aiAgain")));
    }

    langToggle.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-l]");
      if (b) paintResult(b.dataset.l);
    });

    if (savedAI) paintResult(getLang() === "ar" ? "ar" : "en");

    let controller = null;
    runBtn.addEventListener("click", async () => {
      if (controller) { controller.abort(); controller = null; }
      controller = new AbortController();
      runBtn.disabled = true;
      langToggle.hidden = true;
      takeBtn.disabled = true;
      takeHost.replaceChildren();
      out.textContent = "";
      out.dir = "ltr"; out.lang = "en";
      out.style.color = "";
      out.classList.add("is-streaming");
      out.scrollIntoView({ block: "nearest", behavior: "smooth" });
      badgeHost.replaceChildren(el("span", { class: "ai-badge", text: t("portal.aiWriting") }));
      let typed = "";
      try {
        const final = await streamAnalysis(r.id, {
          signal: controller.signal,
          onDelta: (d) => { typed += d; out.textContent = typed; },
        });
        result = final;
        out.classList.remove("is-streaming");
        try { localStorage.setItem(cacheKey, JSON.stringify(final)); } catch { /* quota */ }
        paintResult("en");
        runBtn.disabled = false;
      } catch (err) {
        out.classList.remove("is-streaming");
        if (err?.name === "AbortError") { runBtn.disabled = false; return; }
        // network-pull mid-stream: keep what we typed, finish with the template
        const { getFallback } = await import("./portal_fallback.js");
        const fb = await getFallback(r.id, typed);
        result = fb;
        try { localStorage.setItem(cacheKey, JSON.stringify(fb)); } catch { /* quota */ }
        paintResult("en");
        toast(t("portal.aiStreamDied"), { kind: "bad" });
        runBtn.disabled = false;
      }
    });

    takeBtn.addEventListener("click", async () => {
      takeBtn.disabled = true;
      const tLabel = takeBtn.lastChild.textContent;
      takeBtn.lastChild.textContent = t("portal.takedownWriting");
      try {
        const { letter_en } = await getTakedown(r.id);
        const letter = el("div", { class: "stack", style: "gap:var(--s2)" },
          el("div", { class: "card-title", style: "margin:0; font-size:var(--fs-sm)" }, el("span", { text: t("portal.takedownTitle") })),
          el("textarea", { class: "textarea", readonly: true, dir: "ltr", lang: "en", style: "min-height:240px; font-size:var(--fs-xs)" }),
          el("div", { class: "row" },
            copyBtn()));
        letter.querySelector("textarea").value = letter_en;
        takeHost.replaceChildren(letter);
        function copyBtn() {
          const b = el("button", { class: "btn btn-sm" }, el("span", { html: icons.copy({ size: 14 }) }), document.createTextNode(t("portal.takedownCopy")));
          b.addEventListener("click", async () => {
            try { await navigator.clipboard.writeText(letter_en); toast(t("portal.takedownCopied"), { kind: "good" }); }
            catch { letter.querySelector("textarea").select(); }
          });
          return b;
        }
      } catch {
        toast(t("common.errorBody"), { kind: "bad" });
      } finally {
        takeBtn.disabled = false;
        takeBtn.lastChild.textContent = tLabel;
      }
    });

    return { node };
  }

  // export the report as JSON (evidence pack download)
  const exportBtn = el("button", { class: "btn btn-sm" }, el("span", { html: icons.down({ size: 16 }) }), document.createTextNode(t("common.exportJson")));
  exportBtn.addEventListener("click", () => {
    const r = reports.find((x) => x.id === selectedId);
    if (!r) return;
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `daggers-report-${r.id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(t("portal.exportDone"), { kind: "good" });
  });
  root.querySelector(".page-head .row, .page-head")?.append(exportBtn);

  if (state.offline) root.prepend(el("div", { class: "note", style: "margin-block-end:var(--s4)" }, el("span", { text: "⊘" }), el("span", { text: t("portal.offlineNote") })));

  return root;
}
