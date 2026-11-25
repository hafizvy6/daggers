/* Daggers · Police Portal — the investigator's workspace.
   All findings (Checker, investigations, radar, sweeps) with search + filters ·
   investigations · reports with AI analysis and takedown drafts · operations.
   Every number and row here comes from the live database. */
import { t, fmtNum, fmtDateTime, timeAgo, getLang, reasonsOf } from "../i18n/i18n.js";
import { getReports, advanceReport, streamAnalysis, getTakedown, tagFor, state, can, AuthError,
  investigate, getInvestigations, listSweeps, getGuardSync, getAudit, logout, searchFindings } from "../api.js";
import { el, tagChip, chip, reasonChip } from "../components/tag.js";
import { evidenceFrame } from "../components/evidence.js";
import { toast } from "../components/toast.js";
import { emptyState, errorCard } from "../components/empty.js";
import { cardsSkeleton } from "../components/skeleton.js";
import { pageHead, card, kv, authGate } from "./_shared.js";
import { icons } from "../components/icons.js";
import { sourceLabel } from "../components/analysis.js";

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
  } catch (err) {
    if (err instanceof AuthError) {
      split.replaceWith(authGate(err));
      return root;
    }
    tableHost.replaceChildren(errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") }));
    return root;
  }
  if (state.user) root.insertBefore(workspace(), statsHost);
  root.insertBefore(el("h2", { text: t("portal.reportsTitle") }), statsHost);
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
        el("td", {}, tagChip(tagFor(r.evidence || r))),
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
    const tagKey = tagFor(ev);

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

    // The stored analysis comes from the server (report.ai); nothing is kept on the device.
    const savedAI = r.ai || null;
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
        paintResult("en");
        runBtn.disabled = false;
      } catch (err) {
        out.classList.remove("is-streaming");
        if (err?.name === "AbortError") { runBtn.disabled = false; return; }
        if (err instanceof AuthError) { out.replaceWith(authGate(err)); runBtn.disabled = false; return; }
        // The stream failed: say so. Partial text is kept but marked incomplete; nothing is substituted.
        out.textContent = typed ? `${typed}\n\n${t("portal.aiIncomplete")}` : t("portal.aiFailed");
        badgeHost.replaceChildren(el("span", { class: "ai-badge is-fallback", text: t("portal.aiFailedTag") }));
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

/* ---------------- Investigations + operations (live, signed-in) ------- */
function workspace() {
  const host = el("div", { class: "stack", style: "margin-block-end:var(--s4)" });
  const signOut = el("button", { class: "btn btn-sm", type: "button", text: t("auth.signOut") });
  signOut.addEventListener("click", async () => { await logout(); location.hash = "#/login"; });
  host.append(state.user.local
    ? el("div", { class: "note note-teal" }, el("span", { text: "i" }), el("span", { text: t("auth.localAccess") }))
    : el("div", { class: "row", style: "justify-content:space-between" },
      el("span", { class: "muted", text: t("auth.signedInAs", { user: state.user.username, role: t(`auth.role_${state.user.role}`) }) }),
      signOut));

  host.append(findingsIndex());

  const invList = el("div", { class: "card flush" }, cardsSkeleton(1));
  if (can("investigator")) host.append(investigateForm());
  else host.append(el("div", { class: "note" }, el("span", { text: "i" }), el("span", { text: t("inv.needInvestigator") })));
  host.append(el("h2", { text: t("inv.listTitle") }), invList);
  paintInvestigations(invList);

  const ops = el("div", { class: "grid-2", style: "align-items:start" });
  host.append(el("h2", { text: t("ops.title") }), ops);
  paintOps(ops);
  return host;
}

function investigateForm() {
  const urlIn = el("input", { class: "input", id: "invUrl", type: "url", dir: "ltr", required: true,
    maxlength: "2048", placeholder: t("inv.urlPlaceholder") });
  const textIn = el("textarea", { class: "textarea", id: "invText", dir: "auto", maxlength: "8000", rows: "3" });
  const msg = el("p", { class: "field-hint", role: "alert" });
  const btn = el("button", { class: "btn btn-primary", type: "submit", text: t("inv.submit") });
  const form = el("form", { class: "stack", novalidate: true },
    el("div", { class: "field" }, el("label", { for: "invUrl", text: t("inv.urlLabel") }), urlIn),
    el("div", { class: "field" }, el("label", { for: "invText", text: t("inv.textLabel") }), textIn,
      el("span", { class: "field-hint", text: t("inv.textHint") })),
    el("div", { class: "row" }, btn), msg);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!urlIn.value.trim()) return;
    btn.disabled = true; btn.textContent = t("inv.submitting"); msg.textContent = "";
    try {
      const finding = await investigate(urlIn.value.trim(), textIn.value.trim());
      location.hash = `#/finding/${finding.id}`;
    } catch (err) {
      msg.textContent = err instanceof AuthError ? t("auth.forbiddenBody") : err?.status === 422 ? t("inv.invalid") : t("inv.error");
      btn.disabled = false; btn.textContent = t("inv.submit");
    }
  });
  return card(t("inv.title"), t("inv.kicker"), form);
}

async function paintInvestigations(host) {
  let rows = [];
  try { rows = await getInvestigations(); } catch (err) {
    host.replaceChildren(err instanceof AuthError ? authGate(err) : errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") }));
    return;
  }
  if (!rows.length) { host.replaceChildren(emptyState({ title: t("inv.empty"), body: "" })); return; }
  const table = el("table", { class: "table" });
  table.append(el("thead", {}, el("tr", {},
    el("th", { text: t("inv.colId") }), el("th", { text: t("inv.colDomain") }), el("th", { text: t("inv.colTag") }),
    el("th", { text: t("inv.colVerification") }), el("th", { text: t("inv.colWhen") }))));
  const tbody = el("tbody");
  rows.slice(0, 25).forEach((f) => {
    const gov = f.gov_verification?.status;
    const tr = el("tr", { tabindex: "0" },
      el("td", { class: "mono" }, el("a", { href: `#/finding/${f.id}`, text: `#${f.id}` })),
      el("td", { class: "ltr", text: f.domain }),
      el("td", {}, tagChip(tagFor(f))),
      el("td", { text: gov ? t(`trust.gov_${gov}`) : "—" }),
      el("td", { class: "mono ltr", text: f.created_at ? timeAgo(f.created_at) : "—" }));
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = `#/finding/${f.id}`; });
    tbody.append(tr);
  });
  table.append(tbody);
  host.replaceChildren(el("div", { class: "table-wrap" }, table));
}

async function paintOps(host) {
  const sweepsCard = card(t("ops.sweepRuns"), "", cardsSkeleton(1));
  const guardCard = card(t("ops.guardSync"), "", cardsSkeleton(1));
  host.append(sweepsCard, guardCard);
  try {
    const runs = await listSweeps();
    const body = runs.length ? el("div", { class: "table-wrap" }, el("table", { class: "table" },
      el("thead", {}, el("tr", {}, el("th", { text: t("ops.colRun") }), el("th", { text: t("ops.colQuery") }),
        el("th", { text: t("ops.colStatus") }), el("th", { text: t("ops.colResults") }))),
      el("tbody", {}, ...runs.slice(0, 10).map((r) => el("tr", {},
        el("td", { class: "mono", text: `#${r.id}` }),
        el("td", { dir: "auto", text: r.query }),
        el("td", { text: `${t(`ops.status_${r.status || "completed"}`)}${r.source_kind ? " · " + t(`ops.kind_${r.source_kind}`) : ""}` }),
        el("td", { class: "mono ltr", text: String(r.result_count ?? 0) })))))) : el("p", { class: "muted", text: t("ops.noRuns") });
    sweepsCard.lastChild.replaceWith(body);
  } catch { sweepsCard.lastChild.replaceWith(el("p", { class: "muted", text: t("common.errorBody") })); }
  try {
    const g = await getGuardSync();
    guardCard.lastChild.replaceWith(el("div", { class: "stack" },
      el("p", { text: t("ops.blocked", { n: fmtNum(g.blocked_domains ?? 0) }) }),
      el("p", { class: "muted", text: t("ops.syncState", { state: g.status }) }),
      el("p", { class: "muted", style: "font-size:var(--fs-xs)", text: t("ops.notMeasured") })));
  } catch { guardCard.lastChild.replaceWith(el("p", { class: "muted", text: t("common.errorBody") })); }
  if (can("admin")) {
    const auditCard = card(t("ops.auditTitle"), "", cardsSkeleton(1));
    host.append(auditCard);
    try {
      const entries = await getAudit();
      auditCard.lastChild.replaceWith(entries.length ? el("div", { class: "table-wrap" }, el("table", { class: "table" },
        el("thead", {}, el("tr", {}, el("th", { text: t("ops.colAt") }), el("th", { text: t("ops.colUser") }),
          el("th", { text: t("ops.colAction") }), el("th", { text: t("ops.colOutcome") }))),
        el("tbody", {}, ...entries.slice(0, 20).map((a) => el("tr", {},
          el("td", { class: "mono ltr", text: timeAgo(a.at) }), el("td", { class: "ltr", text: a.username || "—" }),
          el("td", { class: "mono ltr", text: a.action }), el("td", { text: a.outcome })))))) : el("p", { class: "muted", text: t("ops.auditEmpty") }));
    } catch { auditCard.lastChild.replaceWith(el("p", { class: "muted", text: t("common.errorBody") })); }
  }
}

/* ---------------- All findings: search + filters (live database) -------- */
const PAGE = 25;

function findingsIndex() {
  const saved = (() => { try { return JSON.parse(sessionStorage.getItem("daggers:portalFilters") || "{}"); } catch { return {}; } })();
  const filters = { q: "", tag: "", input_type: "", source: "", date_from: "", date_to: "", offset: 0, ...saved };

  const q = el("input", { class: "input", id: "fQ", type: "search", dir: "auto", maxlength: "200",
    placeholder: t("portal.findPlaceholder"), value: filters.q });
  const sel = (id, name, options) => {
    const s = el("select", { class: "select", id });
    for (const [value, key] of options) {
      const o = el("option", { value, text: t(key) });
      if (filters[name] === value) o.selected = true;
      s.append(o);
    }
    return s;
  };
  const tagSel = sel("fTag", "tag", [["", "portal.anyVerdict"], ["FAKE", "common.tagFake"], ["MISLEADING", "common.tagMisleading"],
    ["WARNING", "common.tagWarning"], ["SAFE", "common.tagSafe"]]);
  const typeSel = sel("fType", "input_type", [["", "portal.anyType"], ["url", "analysis.type_url"], ["text", "analysis.type_text"],
    ["domain", "analysis.type_domain"]]);
  const srcSel = sel("fSource", "source", [["", "portal.anySource"], ["checker", "analysis.src_checker"],
    ["investigation", "analysis.src_investigation"], ["sweep", "analysis.src_sweep"], ["crt", "analysis.src_crt"],
    ["feeds", "analysis.src_feeds"], ["radar", "analysis.src_radar"]]);
  const from = el("input", { class: "input", id: "fFrom", type: "date", value: filters.date_from });
  const to = el("input", { class: "input", id: "fTo", type: "date", value: filters.date_to });
  const field = (id, key, ctrl) => el("div", { class: "field" }, el("label", { for: id, text: t(key) }), ctrl);
  const apply = el("button", { class: "btn btn-primary", type: "submit", text: t("portal.applyFilters") });
  const reset = el("button", { class: "btn btn-ghost", type: "button", text: t("portal.resetFilters") });
  const form = el("form", { class: "filters", role: "search" },
    field("fQ", "portal.findLabel", q), field("fTag", "portal.colTag", tagSel), field("fType", "analysis.inputType", typeSel),
    field("fSource", "common.source", srcSel), field("fFrom", "portal.dateFrom", from), field("fTo", "portal.dateTo", to),
    el("div", { class: "row" }, apply, reset));

  const summary = el("p", { class: "muted", role: "status", style: "font-size:var(--fs-sm); margin:0" });
  const tableHost = el("div", { class: "card flush", id: "findingsTable" }, cardsSkeleton(1));
  const pager = el("div", { class: "pager" });
  const box = el("section", { class: "stack", id: "portalFindings" },
    el("h2", { text: t("portal.findingsTitle") }),
    el("p", { class: "muted", style: "margin:0", text: t("portal.findingsNote") }),
    el("div", { class: "card" }, form), summary, tableHost, pager);

  const read = () => {
    filters.q = q.value.trim(); filters.tag = tagSel.value; filters.input_type = typeSel.value;
    filters.source = srcSel.value; filters.date_from = from.value; filters.date_to = to.value;
  };
  form.addEventListener("submit", (e) => { e.preventDefault(); read(); filters.offset = 0; load(); });
  reset.addEventListener("click", () => {
    q.value = ""; tagSel.value = ""; typeSel.value = ""; srcSel.value = ""; from.value = ""; to.value = "";
    read(); filters.offset = 0; load();
  });

  async function load() {
    try { sessionStorage.setItem("daggers:portalFilters", JSON.stringify(filters)); } catch { /* private mode */ }
    tableHost.replaceChildren(cardsSkeleton(1));
    let data;
    try {
      data = await searchFindings({ ...filters, limit: PAGE });
    } catch (err) {
      tableHost.replaceChildren(err instanceof AuthError ? authGate(err)
        : errorCard({ title: t("common.errorTitle"), body: t("portal.findingsError") }));
      summary.textContent = ""; pager.replaceChildren();
      return;
    }
    const facets = data.facets?.tag || {};
    summary.textContent = t("portal.findingsCount", { n: fmtNum(data.total) }) + "  ·  " +
      ["FAKE", "MISLEADING", "WARNING", "SAFE"].map((k) => `${t(`common.tag${k[0]}${k.slice(1).toLowerCase()}`)} ${fmtNum(facets[k] || 0)}`).join(" · ");
    if (!data.findings.length) {
      tableHost.replaceChildren(emptyState({ title: t("portal.noFindings"), body: t("portal.noFindingsBody") }));
      pager.replaceChildren();
      return;
    }
    const table = el("table", { class: "table", id: "findingsTableEl" });
    table.append(el("thead", {}, el("tr", {},
      el("th", { text: t("inv.colId") }), el("th", { text: t("portal.colTag") }), el("th", { text: t("analysis.inputType") }),
      el("th", { text: t("portal.colSubject") }), el("th", { text: t("common.source") }), el("th", { text: t("inv.colWhen") }))));
    const tbody = el("tbody");
    for (const f of data.findings) {
      const subject = f.submitted_input || f.submitted_url || f.domain || "—";
      const tr = el("tr", { tabindex: "0", "data-finding": String(f.id) },
        el("td", { class: "mono" }, el("a", { href: `#/finding/${f.id}`, text: `#${f.id}` })),
        el("td", {}, tagChip(tagFor(f))),
        el("td", { text: t(`analysis.type_${f.input_type || "domain"}`) }),
        el("td", { class: "col-domain", dir: "auto", title: subject, text: subject.length > 90 ? subject.slice(0, 90) + "…" : subject }),
        el("td", { text: sourceLabel(f) }),
        el("td", { class: "mono ltr", title: fmtDateTime(f.created_at || f.first_seen), text: timeAgo(f.created_at || f.first_seen) }));
      tr.addEventListener("click", (e) => { if (!e.target.closest("a")) location.hash = `#/finding/${f.id}`; });
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = `#/finding/${f.id}`; });
      tbody.append(tr);
    }
    table.append(tbody);
    tableHost.replaceChildren(el("div", { class: "table-wrap" }, table));
    const prev = el("button", { class: "btn btn-sm", type: "button", text: t("portal.prev"), disabled: filters.offset === 0 });
    const next = el("button", { class: "btn btn-sm", type: "button", text: t("portal.next"),
      disabled: filters.offset + PAGE >= data.total });
    prev.addEventListener("click", () => { filters.offset = Math.max(0, filters.offset - PAGE); load(); });
    next.addEventListener("click", () => { filters.offset += PAGE; load(); });
    pager.replaceChildren(el("span", { class: "muted mono", text: `${filters.offset + 1}–${Math.min(filters.offset + PAGE, data.total)} / ${data.total}` }), prev, next);
  }
  load();
  return box;
}
