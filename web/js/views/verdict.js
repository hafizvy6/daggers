/* Daggers · Verdict interstitial — standalone minimal data view used by the
   Guard's fallback pages and deep links (#/verdict/:domain). */
import { t, localized, reasonsOf } from "../i18n/i18n.js";
import { getFeed, tagFor } from "../api.js";
import { el, tagChip, reasonChip } from "../components/tag.js";
import { emptyState } from "../components/empty.js";
import { pageHead, card } from "./_shared.js";
import { icons } from "../components/icons.js";

export default async function VerdictPage(ctx) {
  const domain = ctx.param || "";
  const root = el("div");
  root.append(pageHead({ kicker: t("verdictpage.kicker"), title: t("verdictpage.blockedFile") }));

  let finding = null;
  try {
    const feed = await getFeed();
    finding = feed.find((f) => f.domain === domain) || null;
  } catch { /* ignore */ }

  if (!finding) {
    root.append(emptyState({ title: t("common.notFoundTitle"), body: t("common.notFoundBody") }));
    return root;
  }
  const tagKey = tagFor(finding.verdict);
  const c = el("section", { class: "card", style: "border-width:3px" });
  c.append(
    el("div", { class: "row", style: "justify-content:space-between" },
      tagChip(tagKey, { size: "xl" }),
      el("span", { class: "mono ltr", style: "font-size:var(--fs-xl); font-weight:600", text: (finding.score ?? 0).toFixed(2) }),
    ),
    el("div", { class: "vh-domain", text: finding.domain }),
    el("p", { class: "vh-why", text: localized(finding, "verdict_note") || "" }),
  );
  if (finding.reasons?.length) {
    c.append(el("div", { style: "margin-block-start:var(--s3)" },
      el("div", { class: "card-title", style: "font-size:var(--fs-sm)", text: t("verdictpage.whyTitle") }),
      el("div", { class: "chips" }, ...reasonsOf(finding).slice(0, 3).map(reasonChip))));
  }
  const row = el("div", { class: "row", style: "margin-block-start:var(--s4)" });
  row.append(
    el("a", { class: "btn btn-primary", href: `#/finding/${finding.id}` }, el("span", { html: icons.doc({ size: 16 }) }), document.createTextNode(t("verdictpage.cta"))),
    el("a", { class: "btn", href: "#/check", text: t("verdictpage.back") }),
  );
  c.append(row);
  c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s3)", text: t("verdictpage.protectNote") }));
  root.append(c);
  return root;
}
