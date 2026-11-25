/* Daggers · Feed — the radar (plan Scenario 6). Live SSE prepend + NEW glow. */
import { t, timeAgo, fmtNum } from "../i18n/i18n.js";
import { getFeed, onState, tagFor, state } from "../api.js";
import { el, tagChip, dot, scoreBar, TAGS } from "../components/tag.js";
import { feedSkeleton } from "../components/skeleton.js";
import { emptyState, errorCard } from "../components/empty.js";
import { pageHead, card } from "./_shared.js";

const SEEN_KEY = "daggers.feed.seen";

export default async function Feed(ctx) {
  const root = el("div");
  root.append(pageHead({
    kicker: t("feed.kicker"),
    title: t("feed.title"),
    subtitle: t("feed.subtitle"),
    actions: [el("span", { class: "chip", title: t("feed.liveNote") },
      el("span", { class: "chip-k", text: "●" }),
      el("span", { class: "mono", text: state.apiDown ? t("top.down") : t("top.live") }))],
  }));

  const filterHost = el("div", { class: "tabs", role: "tablist", "aria-label": t("feed.title") });
  const listHost = el("div", { class: "card flush" }).append(
    el("div", { class: "sk sk-row", style: "margin:0; height:52px" }),
  ) && el("div");

  const wrap = el("div", { class: "stack" });
  root.append(wrap);

  let findings = [];
  let filter = "all";
  let live = true;

  wrap.append(el("div", { class: "row", style: "gap:var(--s3)" }, filterHost,
    el("span", { class: "card-kicker mono", id: "feedCount", style: "margin-inline-start:auto" })));
  const listCard = el("div", { class: "card flush" }, feedSkeleton(6));
  wrap.append(listCard);

  const tabs = [
    { id: "all", key: "feed.filterAll" },
    { id: "malicious", key: "feed.filterMalicious" },
    { id: "suspicious", key: "feed.filterSuspicious" },
  ];
  const paintTabs = () => {
    filterHost.replaceChildren(...tabs.map((tb) => {
      const b = el("button", { role: "tab", "aria-selected": String(tb.id === filter), text: t(tb.key) });
      b.addEventListener("click", () => { filter = tb.id; paintTabs(); paintList(); });
      return b;
    }));
  };
  paintTabs();

  function rowFor(f, isNew) {
    const tagKey = tagFor(f);
    const a = el("a", { class: `feed-row${isNew ? " is-new" : ""}`, href: `#/finding/${f.id}`, "data-id": f.id });
    a.append(
      dot(tagKey),
      el("span", { class: "fr-domain" },
        el("span", { class: "ltr", text: f.domain }),
        isNew ? el("span", { class: "new-flag", text: t("feed.new") }) : null),
      el("span", { class: "tag-cell" }, tagChip(tagKey, { size: "" })),
      el("span", { class: "fr-clone", text: f.clone != null ? `${f.clone}%` : "—" }),
      scoreBar(tagKey, f.score),
      el("span", { class: "fr-source", text: f.source || "" }),
    );
    // mobile meta line
    return a;
  }

  function paintList(newIds = new Set()) {
    const shown = findings.filter((f) => filter === "all" || tagFor(f) === filter);
    document.getElementById("feedCount") && (document.getElementById("feedCount").textContent = t("feed.count", { n: fmtNum(shown.length) }));
    if (!shown.length) {
      listCard.replaceChildren(emptyState({
        title: t("feed.emptyTitle"), body: t("feed.emptyBody"),
      }));
      return;
    }
    const list = el("div", { class: "feed-list", role: "list" });
    shown.forEach((f) => list.append(rowFor(f, newIds.has(f.id))));
    listCard.replaceChildren(list);
  }

  try {
    findings = await getFeed();
    // mark everything already seen as not-new
    const seen = new Set(JSON.parse(sessionStorage.getItem(SEEN_KEY) || "[]"));
    paintList();
    findings.forEach((f) => seen.add(f.id));
    sessionStorage.setItem(SEEN_KEY, JSON.stringify([...seen]));
  } catch (err) {
    listCard.replaceChildren(errorCard({
      title: t("common.errorTitle"), body: t("common.errorBody"),
      retryLabel: t("common.retry"),
      retry: () => ctx.app && import("../app.js").then((m) => m.navigate(true)),
    }));
  }

  // live prepend
  const hook = (finding) => {
    if (!finding || findings.some((f) => f.id === finding.id)) return;
    findings.unshift(finding);
    paintList(new Set([finding.id]));
  };
  ctx.app.streamHooks.push(hook);
  if (ctx.app.armDemoBeat) ctx.app.armDemoBeat();
  root._cleanup = () => {
    const i = ctx.app.streamHooks.indexOf(hook);
    if (i >= 0) ctx.app.streamHooks.splice(i, 1);
  };

  return root;
}
