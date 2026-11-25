/* Daggers · Finding — the complete stored analysis of one finding.
   Same renderer as the Checker (components/analysis.js), so the portal shows exactly
   what the Checker showed. Evidence screenshots appear only when one was really captured. */
import { t, fmtDateTime, timeAgo } from "../i18n/i18n.js";
import { getFinding, fileReport, getReports, tagFor, AuthError, can, state } from "../api.js";
import { el, chip } from "../components/tag.js";
import { evidenceFrame } from "../components/evidence.js";
import { toastFiled } from "../components/toast.js";
import { cardsSkeleton } from "../components/skeleton.js";
import { emptyState } from "../components/empty.js";
import { analysisView, sourceLabel } from "../components/analysis.js";
import { pageHead, card, kv, authGate } from "./_shared.js";
import { icons } from "../components/icons.js";

export default async function Finding(ctx) {
  const id = Number(ctx.param);
  const root = el("div");
  root.append(pageHead({ kicker: t("finding.kicker", { id }), title: t("finding.title"), actions: [backLink()] }));
  const body = el("div", { class: "stack" }, cardsSkeleton(2));
  root.append(body);

  let f = null;
  try {
    f = await getFinding(id);
  } catch (err) {
    if (err instanceof AuthError) { body.replaceWith(authGate(err)); return root; }
  }
  if (!f) {
    body.replaceWith(emptyState({ title: t("finding.notFoundTitle"), body: t("finding.notFoundBody"), action: backLink() }));
    return root;
  }

  const reports = state.user ? await getReports().catch(() => []) : [];
  const existing = reports.find((r) => r.finding_id === f.id);

  const content = el("div", { class: "stack" });
  content.append(el("div", { class: "chips" },
    chip(t("common.source"), sourceLabel(f)),
    f.investigator ? chip(t("trust.investigator"), f.investigator) : null,
    f.created_at ? chip(t("analysis.recorded"), timeAgo(f.created_at)) : null));

  const grid = el("div", { class: "split" });
  const main = analysisView(f);
  const side = el("div", { class: "stack" });
  if (f.evidence_url) side.append(evidenceFrame(f, { compact: false }));
  side.append(factsCard(f), timelineCard(f, existing), reportCard(f, existing));
  grid.append(main, side);
  content.append(grid);
  body.replaceWith(content);
  return root;
}

function factsCard(f) {
  return card(t("finding.factsTitle"), "", kv([
    [t("analysis.findingIdLabel"), el("span", { class: "ltr mono", text: `#${f.id}` })],
    f.domain ? [t("common.domain"), el("span", { class: "ltr", text: f.domain })] : null,
    f.submitted_url ? [t("trust.submittedUrl"), el("span", { class: "ltr mono", text: f.submitted_url })] : null,
    f.cert_issued && f.source !== "checker" ? [t("finding.certIssued"), fmtDateTime(f.cert_issued)] : null,
    f.first_seen ? [t("finding.firstSeen"), fmtDateTime(f.first_seen)] : null,
    f.gallery_match ? [t("finding.galleryMatch"), f.gallery_match] : null,
  ]));
}

/* Only events that are actually recorded. */
function timelineCard(f, report) {
  const events = [];
  if (f.first_seen && f.source !== "checker") events.push({ when: f.first_seen, what: t("finding.tlDomain") });
  events.push({ when: f.scanned_at || f.created_at || f.first_seen,
    what: t("finding.tlAnalysed", { tag: t(`common.tag${cap(tagFor(f))}`) }), key: true });
  if (report) events.push({ when: report.filed_at || report.created_at, what: t("finding.tlFiled") });
  const tl = el("ol", { class: "timeline" });
  for (const e of events.filter((x) => x.when)) {
    tl.append(el("li", { class: e.key ? "is-key" : "" },
      el("span", { class: "tl-when", text: fmtDateTime(e.when) }), el("span", { class: "tl-what", text: e.what })));
  }
  return card(t("finding.timelineTitle"), "", tl);
}

function reportCard(f, existing) {
  const c = el("section", { class: "card", style: "border-color:var(--accent); background:var(--accent-tint)" });
  c.append(el("div", { class: "card-title" }, el("span", { text: t("finding.reportTitle") })),
    el("p", { style: "font-size:var(--fs-sm)", text: t("finding.reportBody") }));
  if (existing) {
    c.append(el("a", { class: "btn btn-ink btn-block", href: `#/portal/${existing.id}` },
      el("span", { html: icons.portal({ size: 18 }) }), document.createTextNode(t("finding.reportFiledBtn"))),
    el("p", { class: "muted mono", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)",
      text: t("finding.reportFiled", { status: t(`portal.${existing.status.toLowerCase()}`) }) }));
    return c;
  }
  if (!can("investigator")) { c.append(authGate(state.user ? { status: 403 } : null)); return c; }
  const btn = el("button", { class: "btn btn-primary btn-lg btn-block" },
    el("span", { html: icons.doc({ size: 18 }) }), document.createTextNode(t("finding.reportBtn")));
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.lastChild.textContent = t("finding.filing");
    try {
      const r = await fileReport(f.id);
      toastFiled();
      btn.replaceWith(el("a", { class: "btn btn-ink btn-block", href: `#/portal/${r.id}` },
        el("span", { html: icons.portal({ size: 18 }) }), document.createTextNode(t("finding.reportFiledBtn"))));
    } catch {
      btn.disabled = false;
      btn.lastChild.textContent = t("finding.reportBtn");
      const { errorCard } = await import("../components/empty.js");
      c.append(errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") }));
    }
  });
  c.append(btn);
  return c;
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

function backLink(label = t("common.back")) {
  const a = el("a", { class: "btn btn-ghost btn-sm", href: state.user ? "#/portal" : "#/feed" },
    el("span", { html: icons.back({ size: 16 }), class: "back-ico" }), document.createTextNode(` ${label}`));
  a.querySelector(".back-ico").style.display = "inline-flex";
  return a;
}
