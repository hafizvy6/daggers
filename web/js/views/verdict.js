/* Daggers · Verdict page — what a blocked visit lands on (/verdict?domain=… → #/verdict/:domain),
   and the Guard's "Preview verdict". Data comes from GET /api/guard/verdict (the live Guard list).
   A real DNS-redirected visit (hit=1) is counted once, anonymously. EN/AR via t(). */
import { t, timeAgo } from "../i18n/i18n.js";
import { guardVerdict, state } from "../api.js";
import { el, tagChip } from "../components/tag.js";
import { pageHead } from "./_shared.js";
import { icons } from "../components/icons.js";

const SOURCES = new Set(["radar", "sweep", "checker", "investigation", "seed"]);

export default async function VerdictPage(ctx) {
  const domain = String(ctx.param || "").trim().toLowerCase().slice(0, 253);
  const root = el("div");
  root.append(pageHead({ kicker: t("verdictpage.kicker"), title: t("verdictpage.blockedFile") }));

  const hitFor = sessionStorage.getItem("daggers:verdictHit");
  const hit = !!domain && hitFor === domain;
  if (hitFor) sessionStorage.removeItem("daggers:verdictHit");

  let data = null;
  let failed = false;
  if (domain) {
    try { data = await guardVerdict(domain, hit); } catch { failed = true; }
  }

  const c = el("section", { class: "card", style: "border-width:3px" });
  if (!domain || failed || !data?.valid) {
    c.append(el("p", { text: failed ? t("verdictpage.unavailable") : t("verdictpage.noDomain") }));
    c.append(backRow());
    root.append(c);
    return root;
  }

  if (!data.blocked) {
    c.append(
      el("div", { class: "vh-domain mono ltr", text: data.domain }),
      el("p", { class: "vh-why", text: t("verdictpage.notListed") }),
      el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("verdictpage.notListedHint") }));
    const checkBtn = el("button", { class: "btn btn-primary", type: "button" }, el("span", { html: icons.check({ size: 16 }) }),
      document.createTextNode(t("verdictpage.checkNow")));
    checkBtn.addEventListener("click", () => {
      sessionStorage.setItem("daggers:share", `https://${data.domain}/`);
      location.hash = "#/check";
    });
    c.append(el("div", { class: "row", style: "margin-block-start:var(--s3)" }, checkBtn,
      el("a", { class: "btn", href: "#/guard", text: t("verdictpage.toGuard") })));
    root.append(c);
    return root;
  }

  const src = SOURCES.has(data.source) ? data.source : "radar";
  c.append(
    el("div", { class: "row", style: "justify-content:space-between" },
      tagChip("fake", { size: "xl" }),
      el("span", { class: "mono ltr", style: "font-size:var(--fs-xl); font-weight:600", text: Number(data.score ?? 0).toFixed(2) })),
    el("div", { class: "vh-domain mono ltr", text: data.domain }),
    el("p", { class: "vh-why", text: t("verdictpage.lead") }));
  if (data.matched && data.matched !== data.domain) {
    c.append(el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("verdictpage.parentMatch", { site: data.matched }) }));
  }
  if (data.reason) {
    c.append(el("div", { style: "margin-block-start:var(--s3)" },
      el("div", { class: "card-title", style: "font-size:var(--fs-sm)", text: t("verdictpage.whyTitle") }),
      el("p", { style: "margin:0; font-size:var(--fs-sm); overflow-wrap:anywhere", text: data.reason })));
  }
  c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)",
    text: t("verdictpage.listedBy", { source: t(`guard.src_${src}`), when: data.listed_at ? timeAgo(data.listed_at) : "—" }) }));

  const actions = el("div", { class: "row", style: "margin-block-start:var(--s4); flex-wrap:wrap" });
  if (data.finding_id && state.user) {
    actions.append(el("a", { class: "btn btn-primary", href: `#/finding/${data.finding_id}` },
      el("span", { html: icons.doc({ size: 16 }) }), document.createTextNode(t("verdictpage.cta"))));
  }
  actions.append(el("a", { class: "btn", href: "#/check", text: t("verdictpage.back") }));
  c.append(actions);
  c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s3)", text: t("verdictpage.protectNote") }));
  c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0", text: t("verdictpage.privacyNote") }));
  root.append(c);
  return root;

  function backRow() {
    return el("div", { class: "row", style: "margin-block-start:var(--s3)" },
      el("a", { class: "btn", href: "#/guard", text: t("verdictpage.toGuard") }),
      el("a", { class: "btn", href: "#/check", text: t("verdictpage.back") }));
  }
}
