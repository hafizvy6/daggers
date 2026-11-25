/* Daggers · Finding detail — the evidence (plan Scenarios 3 + 6).
   Side-by-side evidence, reason chips, score breakdown, facts, timeline,
   FILE REPORT → reports API → toast "We got you." */
import { t, timeAgo, fmtDateTime, localized, reasonsOf } from "../i18n/i18n.js";
import { getFinding, fileReport, getReports, setFindingLabel, tagFor } from "../api.js";
import { el, tagChip, chip, reasonChip, breakdown } from "../components/tag.js";
import { evidenceFrame } from "../components/evidence.js";
import { toastFiled } from "../components/toast.js";
import { cardsSkeleton } from "../components/skeleton.js";
import { emptyState } from "../components/empty.js";
import { pageHead, card, kv, stack } from "./_shared.js";
import { icons } from "../components/icons.js";

export default async function Finding(ctx) {
  const id = Number(ctx.param);
  const root = el("div");
  root.append(pageHead({
    kicker: t("finding.kicker", { id }),
    title: t("finding.title"),
    actions: [backLink()],
  }));
  const body = el("div", { class: "stack" }, cardsSkeleton(2));
  root.append(body);
  root.append(el("div", { class: "stack", id: "foundBody" }));
  root.querySelector("#foundBody").append(body);

  let f = null;
  try {
    f = await getFinding(id);
  } catch { f = null; }

  if (!f) {
    body.replaceWith(emptyState({
      title: t("finding.notFoundTitle"), body: t("finding.notFoundBody"),
      action: backLink(t("common.back")),
    }));
    return root;
  }

  const tagKey = tagFor(f.verdict, f);
  const reports = await getReports().catch(() => []);
  const existing = reports.find((r) => r.finding_id === f.id);

  const grid = el("div", { class: "split" });

  /* left: evidence */
  const left = stack(evidenceFrame(f, { compact: false }));
  const metaRow = el("div", { class: "chips" });
  metaRow.append(
    chip(t("common.source"), f.source || "—"),
    f.cert_issued ? chip(t("finding.certIssued"), timeAgo(f.cert_issued)) : null,
    f.gallery_match ? chip(t("feed.colClone"), `${f.clone ?? 0}%`) : null,
  );
  left.append(el("div", { class: "card tight" }, el("div", { class: "chips" }, ...metaRow.children)));

  /* right: verdict + reasons */
  const right = el("div", { class: "stack" });
  const verdictCard = el("section", { class: "card" });
  verdictCard.append(
    el("div", { class: "row", style: "justify-content:space-between" },
      tagChip(tagKey, { size: "xl" }),
      el("div", { class: "mono ltr", style: "font-size:var(--fs-2xl); font-weight:600", text: (f.score ?? 0).toFixed(2) }),
    ),
    el("div", { class: "vh-domain", style: "font-size:var(--fs-lg)", text: f.domain }),
    el("p", { class: "muted", style: "margin-block-start:var(--s2)", text: localized(f, "verdict_note") || t(TAGS_HINT(tagKey)) }),
  );
  // score bar
  const pct = Math.round((f.score ?? 0) * 100);
  verdictCard.append(el("div", { class: "score-bar", style: "margin-block-start:var(--s3)" },
    el("div", { class: "track" }, el("div", { class: `fill fill-${tagKey}`, style: `--w:${pct}%` }))));

  const reasonsCard = card(t("finding.reasonsTitle"), t("common.evidence"),
    el("p", { class: "muted", style: "margin-block-end:var(--s3); font-size:var(--fs-sm)", text: t("finding.reasonsNote") }),
    el("div", { class: "chips" }, ...reasonsOf(f).map(reasonChip)));

  right.append(verdictCard, reasonsCard);

  if (Array.isArray(f.signals) && f.signals.length) {
    right.append(card(t("finding.breakdownTitle"), "", breakdown(f.signals.map((x) => ({ ...x, label: localized(x, "label") || x.label })))));
  }

  const labelCard = analystLabelCard(f);
  right.append(labelCard);

  /* facts + timeline */
  const factsCard = card(t("finding.factsTitle"), t("finding.kickerEnrich"), kv([
    [t("common.domain"), el("span", { class: "ltr", text: f.domain })],
    [t("finding.certIssued"), f.cert_issued ? `${fmtDateTime(f.cert_issued)} · ${timeAgo(f.cert_issued)}` : null],
    [t("finding.firstSeen"), f.first_seen ? `${fmtDateTime(f.first_seen)} · ${timeAgo(f.first_seen)}` : null],
    [t("finding.registrar"), f.registrar],
    [t("finding.galleryMatch"), f.gallery_match],
    f.maps_listing ? [t("sweep.listingPhone"), el("span", { class: "ltr", text: f.maps_listing.phone })] : null,
    f.maps_listing ? [t("sweep.listingSite"), el("span", { class: "ltr", text: f.maps_listing.website })] : null,
  ]));

  const tl = el("ol", { class: "timeline" });
  const t0 = f.first_seen || new Date().toISOString();
  const verdictKey = { MALICIOUS: "Fake", SUSPICIOUS: "Warning", MISLEADING: "Misleading" }[f.verdict];
  const steps = [
    { when: t0, what: t("finding.tlDomain"), key: false },
    { when: t0, what: t("finding.tlEnriched"), key: false },
    verdictKey
      ? { when: t0, what: t("finding.tlFlagged", { verdict: t(`common.tag${verdictKey}`) }), key: true }
      : { when: t0, what: t("finding.tlReviewed"), key: false },
  ];
  if (["MALICIOUS"].includes(f.verdict)) steps.push({ when: t0, what: t("finding.tlBlocked"), key: false });
  if (existing) steps.push({ when: existing.filed_at || t0, what: t("finding.tlFiled"), key: false });
  for (const s of steps) {
    tl.append(el("li", { class: s.key ? "is-key" : "" },
      el("span", { class: "tl-when", text: fmtDateTime(s.when) }),
      el("span", { class: "tl-what", text: s.what })));
  }
  const timelineCard = card(t("finding.timelineTitle"), "", tl);

  /* report card */
  const reportCard = el("section", { class: "card", style: "border-color:var(--accent); background:var(--accent-tint)" });
  reportCard.append(
    el("div", { class: "card-title" }, el("span", { text: t("finding.reportTitle") })),
    el("p", { style: "font-size:var(--fs-sm)", text: t("finding.reportBody") }),
  );
  if (existing) {
    const btn = el("button", { class: "btn btn-ink btn-block", style: "margin-block-start:var(--s3)" },
      el("span", { html: icons.portal({ size: 18 }) }),
      document.createTextNode(t("finding.reportFiledBtn")));
    btn.addEventListener("click", () => { location.hash = `#/portal/${existing.id}`; });
    reportCard.append(btn);
    reportCard.append(el("p", { class: "muted mono", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)",
      text: t("finding.reportFiled", { status: t(`portal.${existing.status.toLowerCase()}`) }) }));
  } else {
    const btn = el("button", { class: "btn btn-primary btn-lg btn-block", style: "margin-block-start:var(--s3)" },
      el("span", { html: icons.doc({ size: 18 }) }),
      document.createTextNode(t("finding.reportBtn")));
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.lastChild.textContent = t("finding.filing");
      try {
        const r = await fileReport(f.id);
        toastFiled();
        btn.replaceWith(el("a", { class: "btn btn-ink btn-block", href: `#/portal/${r.id}` },
          el("span", { html: icons.portal({ size: 18 }) }),
          document.createTextNode(t("finding.reportFiledBtn"))));
      } catch {
        btn.disabled = false;
        btn.lastChild.textContent = t("finding.reportBtn");
        const { errorCard } = await import("../components/empty.js");
        reportCard.append(errorCard({ title: t("common.errorTitle"), body: t("common.errorBody") }));
      }
    });
    reportCard.append(btn);
  }

  grid.append(left, right);
  body.replaceWith(grid, el("div", { class: "grid-2", style: "margin-block-start:var(--s4); align-items:start" }, factsCard, timelineCard));
  root.append(reportCard);

  return root;
}

function analystLabelCard(finding) {
  const status = el("p", { class: "muted", style: "font-size:var(--fs-sm); margin-block-end:var(--s2)", text: t("finding.labelNote") });
  const current = finding?.analyst_label?.label || null;
  const currentLine = el("p", { class: "mono", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)", text: current ? t("finding.labelCurrent", { label: t(`finding.label${labelKey(current)}`) }) : t("finding.labelUnset") });
  const buttons = el("div", { class: "chips", role: "group", "aria-label": t("finding.labelTitle") });
  const feedback = el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)", text: "" });
  const labels = ["official", "scam", "unrelated", "parked"];
  const paint = (active) => {
    for (const button of buttons.querySelectorAll("button")) {
      button.setAttribute("aria-pressed", String(button.dataset.label === active));
      button.classList.toggle("btn-primary", button.dataset.label === active);
      button.classList.toggle("btn-ghost", button.dataset.label !== active);
    }
    currentLine.textContent = active ? t("finding.labelCurrent", { label: t(`finding.label${labelKey(active)}`) }) : t("finding.labelUnset");
  };
  for (const label of labels) {
    const button = el("button", { class: `btn btn-sm ${label === current ? "btn-primary" : "btn-ghost"}`, "data-label": label, "aria-pressed": String(label === current), text: t(`finding.label${labelKey(label)}`) });
    button.addEventListener("click", async () => {
      button.disabled = true;
      feedback.textContent = t("finding.labelSaving");
      try {
        await setFindingLabel(finding.id, label);
        paint(label);
        finding.analyst_label = { label };
        feedback.textContent = ["official", "unrelated", "parked"].includes(label)
          ? t("finding.labelSuppressed")
          : t("finding.labelMarked");
      } catch {
        feedback.textContent = t("finding.labelSaveFailed");
      } finally {
        button.disabled = false;
      }
    });
    buttons.append(button);
  }
  return card(t("finding.labelTitle"), t("finding.labelKicker"), status, buttons, currentLine, feedback);
}

function labelKey(label) {
  return String(label || "").replace(/^[a-z]/, (char) => char.toUpperCase());
}

function TAGS_HINT(tagKey) {
  const map = { safe: "common.tagSafeHint", warning: "common.tagWarningHint", misleading: "common.tagMisleadingHint", fake: "common.tagFakeHint", unknown: "common.tagUnknownHint" };
  return map[tagKey] || "common.tagUnknownHint";
}

function backLink(label = t("common.back")) {
  const a = el("a", { class: "btn btn-ghost btn-sm", href: "#/feed" },
    el("span", { html: icons.back({ size: 16 }), class: "back-ico" }),
    document.createTextNode(` ${label}`));
  a.querySelector(".back-ico").style.display = "inline-flex";
  return a;
}
