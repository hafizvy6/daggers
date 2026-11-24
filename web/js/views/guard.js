/* Daggers · Guard — one switch, set once (plan Scenarios 1, 2, 10).
   NextDNS steps EN/AR, blocked counter, feed preview. */
import { t, fmtNum } from "../i18n/i18n.js";
import { getGuardConfig, getGuardStats, getFeed, tagFor, state } from "../api.js";
import { el, tagChip } from "../components/tag.js";
import { toast } from "../components/toast.js";
import { pageHead, card } from "./_shared.js";
import { icons } from "../components/icons.js";
import { cardsSkeleton } from "../components/skeleton.js";

export default async function Guard() {
  const root = el("div");
  root.append(pageHead({
    kicker: t("guard.kicker"), title: t("guard.title"), subtitle: t("guard.subtitle"),
  }));

  const statsHost = el("div");
  const stepsHost = el("div", { class: "stack" }, cardsSkeleton(1));
  const feedHost = el("div", { class: "card flush" }, cardsSkeleton(1));
  root.append(statsHost, el("div", { class: "split", style: "margin-block-start:var(--s4)" },
    el("div", { class: "stack" },
      card(t("guard.stateOnTitle"), t("guard.on"), el("p", { style: "font-size:var(--fs-sm)", text: t("guard.stateOnBody") })),
      stepsHost),
    el("div", { class: "stack" }, feedHost),
  ));

  let stats = { blocked_today: 0, feed_size: 0 };
  let guard = { hostname: null, configured: false };
  try {
    [stats, guard] = await Promise.all([getGuardStats(), getGuardConfig()]);
  } catch { /* honest zero/unconfigured state */ }
  const hostname = guard.hostname || "";

  statsHost.append(el("div", { class: "card tight" },
    el("div", { class: "stat-row" },
      stat(fmtNum(stats.blocked_today), t("guard.blockedToday"), true),
      stat(fmtNum(stats.feed_size), t("guard.feedSize")),
      stat(t(guard.configured ? "guard.on" : "guard.off"), t("guard.statusLabel")),
    )));
  if (state.offline) statsHost.prepend(el("div", { class: "note", style: "margin-block-end:var(--s3)" }, el("span", { text: "⊘" }), el("span", { text: t("guard.offlineNote") })));

  /* the 3 steps */
  const hostRow = el("div", { class: "input-row", style: "margin-block-start:var(--s2)" },
    el("input", { class: "input mono ltr", dir: "ltr", readonly: true, value: hostname, placeholder: t("guard.hostUnconfigured"), "aria-label": t("guard.hostLabel") }),
  );
  const copyBtn = el("button", { class: "btn btn-primary", disabled: !hostname }, el("span", { html: icons.copy({ size: 16 }) }), document.createTextNode(t("guard.copyHost")));
  copyBtn.addEventListener("click", async () => {
    if (!hostname) return;
    try { await navigator.clipboard.writeText(hostname); toast(t("guard.copied"), { kind: "good" }); }
    catch { hostRow.querySelector("input").select(); }
  });
  hostRow.append(copyBtn);
  if (!hostname) {
    stepsHost.replaceChildren(el("div", { class: "note" }, el("span", { text: "⊘" }), el("span", { text: t("guard.hostUnconfigured") })));
  }

  const steps = el("ol", { class: "steps", style: "list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:var(--s3)" });
  [
    ["guard.step1Title", "guard.step1Body"],
    ["guard.step2Title", "guard.step2Body"],
  ].forEach(([k, b], i) => {
    steps.append(el("li", { style: "display:flex; gap:var(--s3); align-items:start" },
      el("span", { class: "mono", style: "flex:none; width:26px; height:26px; border:var(--border); border-radius:50%; display:grid; place-items:center; font-size:var(--fs-xs); font-weight:600; background:var(--surface)", text: String(i + 1) }),
      el("div", {}, el("div", { style: "font-weight:600", text: t(k) }), el("div", { class: "muted", style: "font-size:var(--fs-sm)", text: t(b) })),
    ));
  });
  steps.append(el("li", { style: "display:flex; gap:var(--s3); align-items:start" },
    el("span", { class: "mono", style: "flex:none; width:26px; height:26px; border:var(--border); border-radius:50%; display:grid; place-items:center; font-size:var(--fs-xs); font-weight:600; background:var(--accent); color:var(--surface)", text: "3" }),
    el("div", {}, el("div", { style: "font-weight:600", text: t("guard.step3Title") }), hostRow,
      el("div", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s1)", text: t("guard.step3Body") })),
  ));
  if (hostname) stepsHost.replaceChildren(card(t("guard.stepsTitle"), t("guard.stepsBadge"), steps));
  else stepsHost.append(card(t("guard.stepsTitle"), t("guard.stepsBadge"), steps));

  /* feed preview */
  let findings = [];
  try { findings = (await getFeed()).filter((f) => tagFor(f.verdict) === "fake").slice(0, 6); } catch { /* ignore */ }
  const list = el("div", { class: "feed-list" });
  findings.forEach((f) => {
    list.append(el("a", { class: "feed-row", href: `#/finding/${f.id}`, style: "grid-template-columns:18px minmax(0,1fr) auto" },
      el("span", { class: "dot-tag dot-fake" }),
      el("span", { class: "fr-domain", text: f.domain }),
      tagChip("fake")));
  });
  feedHost.replaceChildren(
    el("div", { class: "card-title", style: "padding:var(--s3) var(--s4); margin:0; border-block-end:var(--border)" },
      el("span", { text: t("guard.feedPreviewTitle") })),
    list);

  /* honest limits + family */
  root.append(el("div", { class: "grid-2", style: "margin-block-start:var(--s4)" },
    card(t("guard.honestTitle"), "", el("p", { style: "font-size:var(--fs-sm)", text: t("guard.honestBody") })),
    card(t("guard.familyTitle"), "", el("p", { style: "font-size:var(--fs-sm)", text: t("guard.familyBody") })),
  ));

  return root;

  function stat(num, label, big) {
    return el("div", { class: "stat" },
      el("span", { class: big ? "stat-num ltr" : "stat-label", style: big ? "color:var(--tag-fake-ink)" : "font-weight:600; color:var(--ink)", text: num }),
      el("span", { class: big ? "stat-label" : "stat-label", text: label }));
  }
}
