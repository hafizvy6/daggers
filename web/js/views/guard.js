/* Daggers · Guard — live. Stats + SSE, newest fakes (with source), real DoT/DoH/blocklist
   addresses from the backend (never a made-up hostname), Sync now, and a test bar that runs
   the same engine as the Checker. EN/AR via t(). */
import { t, fmtNum, timeAgo } from "../i18n/i18n.js";
import { getGuardStats, syncGuard, guardCheck, tagFor, state } from "../api.js";
import { el, tagChip } from "../components/tag.js";
import { toast } from "../components/toast.js";
import { pageHead, card } from "./_shared.js";
import { icons } from "../components/icons.js";
import { cardsSkeleton } from "../components/skeleton.js";

const SOURCES = new Set(["radar", "sweep", "checker", "investigation", "seed"]);
const MODES = new Set(["doh_verdict", "doh", "nextdns", "list_only"]);
const HEALTH = new Set(["ok", "error", "rate_limited", "never"]);

export default async function Guard(ctx) {
  const root = el("div");
  root.append(pageHead({ kicker: t("guard.kicker"), title: t("guard.title"), subtitle: t("guard.subtitle") }));

  const statsHost = el("div", {}, cardsSkeleton(1));
  const setupHost = el("div", { class: "stack" }, cardsSkeleton(1));
  const feedHost = el("div", { class: "card flush" }, cardsSkeleton(1));
  const testHost = el("div", { style: "margin-block-start:var(--s4)" });
  const limitsHost = el("div", { class: "grid-2", style: "margin-block-start:var(--s4)" });
  root.append(statsHost, testHost,
    el("div", { class: "split", style: "margin-block-start:var(--s4)" }, setupHost, el("div", { class: "stack" }, feedHost)),
    limitsHost);

  testHost.append(testBar());

  let stats = null;
  async function load() {
    try { stats = await getGuardStats(); } catch { stats = stats || null; }
    render();
  }

  function render() {
    const s = stats || {};
    const on = s.enabled !== false && s.status !== "off";
    const mode = MODES.has(s.guard_mode) ? s.guard_mode : "list_only";
    const health = HEALTH.has(s.sync_health) ? s.sync_health : "never";

    /* stats */
    const statusBox = el("div", { class: "card tight" },
      el("div", { class: "stat-row" },
        stat(fmtNum(s.blocked_today ?? 0), t("guard.blockedToday"), true),
        stat(fmtNum(s.blocklist_count ?? s.feed_size ?? 0), t("guard.feedSize"), true),
        stat(fmtNum(s.blocked_total ?? 0), t("guard.blockedTotal"), true),
        stat(on ? t("guard.on") : t("guard.off"), t("guard.statusLabel")),
      ),
      el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:var(--s2) 0 0", text: t("guard.countedNote") }),
      el("div", { class: "row", style: "margin-block-start:var(--s2); gap:var(--s2); flex-wrap:wrap" },
        badge(t(`guard.mode_${mode}`)),
        badge(t(`guard.sync_${health}`), health === "ok" ? "good" : health === "never" ? "" : "bad"),
        el("span", { class: "muted", style: "font-size:var(--fs-xs)",
          text: s.last_sync_at ? t("guard.lastSync", { when: timeAgo(s.last_sync_at) }) : t("guard.neverSynced") }),
      ));
    if (s.nextdns_configured && s.nextdns_blocked_24h != null) {
      statusBox.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:var(--s1) 0 0",
        text: t("guard.nextdns24h", { n: fmtNum(s.nextdns_blocked_24h) }) }));
    }
    statsHost.replaceChildren(statusBox);
    if (state.offline || s.stale) statsHost.prepend(el("div", { class: "note", style: "margin-block-end:var(--s3)" },
      el("span", { text: "⊘" }), el("span", { text: t("guard.offlineNote") })));
    if (!stats) statsHost.prepend(el("div", { class: "note", style: "margin-block-end:var(--s3)" },
      el("span", { text: "!" }), el("span", { text: t("guard.statsUnavailable") })));

    /* setup: DoT hostname, DoH URL, blocklist URL, Sync now */
    const syncBtn = el("button", { class: "btn" }, el("span", { html: icons.bolt({ size: 16 }) }), document.createTextNode(t("guard.syncNow")));
    syncBtn.addEventListener("click", async () => {
      syncBtn.disabled = true;
      try {
        const r = await syncGuard();
        toast(r?.ok === false ? t("guard.syncFailed") : t("guard.syncDone"), { kind: r?.ok === false ? "bad" : "good" });
      } catch (err) {
        toast(err?.status === 429 ? t("guard.syncCooldown") : t("guard.syncFailed"), { kind: "bad" });
      } finally {
        syncBtn.disabled = false;
        load();
      }
    });

    const steps = el("ol", { class: "steps", style: "list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:var(--s3)" });
    [["guard.step1Title", "guard.step1Body"], ["guard.step2Title", "guard.step2Body"]].forEach(([k, b], i) => {
      steps.append(stepItem(i + 1, el("div", {}, el("div", { style: "font-weight:600", text: t(k) }),
        el("div", { class: "muted", style: "font-size:var(--fs-sm)", text: t(b) }))));
    });
    const step3 = el("div", {}, el("div", { style: "font-weight:600", text: t("guard.step3Title") }));
    if (s.dot_hostname) {
      step3.append(copyRow(s.dot_hostname, t("guard.hostLabel"), t("guard.copyHost")),
        el("div", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s1)", text: t("guard.step3Body") }));
    } else {
      step3.append(el("div", { class: "note", style: "margin-block-start:var(--s2)" },
        el("span", { text: "!" }), el("span", { text: t("guard.dotNotConfigured") })));
    }
    steps.append(stepItem(3, step3, true));

    const links = el("div", { class: "stack", style: "gap:var(--s2)" });
    if (s.doh_url) links.append(label(t("guard.dohLabel")), copyRow(s.doh_url, t("guard.dohLabel"), t("guard.copy")));
    if (s.blocklist_url) links.append(label(t("guard.blocklistLabel")), copyRow(s.blocklist_url, t("guard.blocklistLabel"), t("guard.copy")));
    links.append(el("div", { class: "row", style: "justify-content:space-between; flex-wrap:wrap; gap:var(--s2)" },
      el("span", { class: "muted", style: "font-size:var(--fs-xs)", text: t("guard.syncHint") }), syncBtn));

    setupHost.replaceChildren(
      card(t("guard.stepsTitle"), t("guard.stepsBadge"), steps),
      card(t("guard.linksTitle"), "", links));

    /* newest fakes */
    const list = el("div", { class: "feed-list" });
    const rows = Array.isArray(s.newest_fakes) ? s.newest_fakes : [];
    rows.forEach((r) => list.append(fakeRow(r)));
    if (!rows.length) list.append(el("p", { class: "muted", style: "padding:var(--s4); margin:0; font-size:var(--fs-sm)", text: t("guard.noFakesYet") }));
    feedHost.replaceChildren(
      el("div", { class: "card-title", style: "padding:var(--s3) var(--s4); margin:0; border-block-end:var(--border)" },
        el("span", { text: t("guard.feedPreviewTitle") }),
        el("span", { class: "card-kicker", text: t("guard.liveBadge") })),
      list);

    /* honest limits (per mode) + family */
    limitsHost.replaceChildren(
      card(t("guard.honestTitle"), "", el("p", { style: "font-size:var(--fs-sm)", text: t(`guard.limits_${mode}`) })),
      card(t("guard.familyTitle"), "", el("p", { style: "font-size:var(--fs-sm)", text: t("guard.familyBody") })));
  }

  await load();

  /* live: list changes and real blocks arrive over SSE */
  let pending = null;
  const hook = (event) => {
    if (event?.type === "listed" && event.domain) toast(t("guard.newListed", { domain: event.domain }), { kind: "bad", ms: 5000 });
    clearTimeout(pending);
    pending = setTimeout(load, 400);
  };
  const hooks = ctx?.app?.guardHooks;
  if (hooks) hooks.push(hook);
  root._cleanup = () => {
    clearTimeout(pending);
    if (hooks) { const i = hooks.indexOf(hook); if (i >= 0) hooks.splice(i, 1); }
  };
  return root;

  /* ---------------- pieces ---------------- */
  function testBar() {
    const input = el("input", { class: "input mono ltr", dir: "ltr", type: "text", placeholder: "example.com",
      "aria-label": t("guard.testLabel"), autocomplete: "off", spellcheck: "false" });
    const go = el("button", { class: "btn btn-primary", type: "submit" }, el("span", { html: icons.shield({ size: 16 }) }),
      document.createTextNode(t("guard.testButton")));
    const out = el("div", { style: "margin-block-start:var(--s3)" });
    const form = el("form", { class: "input-row" }, input, go);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = input.value.trim();
      if (!domain) return;
      go.disabled = true;
      out.replaceChildren(el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("guard.testing") }));
      try {
        const r = await guardCheck(domain, true);
        out.replaceChildren(testResult(r));
        if (r?.listed_now) load();
      } catch (err) {
        out.replaceChildren(el("div", { class: "note" }, el("span", { text: "!" }),
          el("span", { text: err?.status === 429 ? t("guard.testRateLimited") : t("guard.testFailed") })));
      } finally { go.disabled = false; }
    });
    return card(t("guard.testTitle"), "", el("p", { class: "muted", style: "font-size:var(--fs-sm); margin-block-start:0", text: t("guard.testBody") }), form, out);
  }

  function testResult(r) {
    const g = r?.guard || {};
    if (!g.valid) return el("div", { class: "note" }, el("span", { text: "!" }), el("span", { text: t("guard.testInvalid") }));
    const box = el("div", { class: "stack", style: "gap:var(--s2)" });
    const scan = r.scan || null;
    const head = el("div", { class: "row", style: "gap:var(--s2); flex-wrap:wrap; align-items:center" },
      el("span", { class: "mono ltr", style: "font-weight:600", text: g.domain }));
    if (scan) head.append(tagChip(tagFor(scan)));
    head.append(badge(g.blocked ? t("guard.testBlocked") : t("guard.testNotBlocked"), g.blocked ? "bad" : ""));
    box.append(head);
    if (scan?.trust_reasons?.length) {
      box.append(el("ul", { style: "margin:0; padding-inline-start:var(--s4); font-size:var(--fs-sm)" },
        ...scan.trust_reasons.slice(0, 3).map((x) => el("li", { text: String(x) }))));
    }
    if (!g.blocked && scan && tagFor(scan) !== "fake") box.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0", text: t("guard.testOnlyFakes") }));
    if (r.listed_now) box.append(el("p", { style: "font-size:var(--fs-sm); margin:0; font-weight:600", text: t("guard.testListedNow") }));
    box.append(el("div", { class: "row", style: "gap:var(--s2)" },
      el("a", { class: "btn", href: `#/verdict/${encodeURIComponent(g.domain)}`, text: t("guard.previewVerdict") })));
    return box;
  }

  function fakeRow(r) {
    const src = SOURCES.has(r.source) ? r.source : "radar";
    const rowEl = el("div", { class: "feed-row", style: "grid-template-columns:18px minmax(0,1fr) auto; align-items:start" },
      el("span", { class: "dot-tag dot-fake" }),
      el("div", { style: "min-width:0" },
        el("div", { class: "fr-domain mono ltr", text: r.domain }),
        el("div", { class: "muted", style: "font-size:var(--fs-xs); overflow-wrap:anywhere", text: r.reason || "" }),
        el("div", { class: "row", style: "gap:var(--s2); margin-block-start:var(--s1); flex-wrap:wrap; font-size:var(--fs-xs)" },
          badge(t(`guard.src_${src}`)),
          el("span", { class: "mono ltr", text: Number(r.score ?? 0).toFixed(2) }),
          el("span", { class: "muted", text: r.listed_at ? timeAgo(r.listed_at) : "" }),
          el("a", { href: `#/verdict/${encodeURIComponent(r.domain)}`, text: t("guard.previewVerdict") }),
          ...(r.finding_id && state.user ? [el("a", { href: `#/finding/${r.finding_id}`, text: t("guard.openFinding") })] : []))),
      tagChip("fake"));
    return rowEl;
  }

  function copyRow(value, aria, btnText) {
    const input = el("input", { class: "input mono ltr", dir: "ltr", readonly: true, value, "aria-label": aria });
    const btn = el("button", { class: "btn btn-primary", type: "button" }, el("span", { html: icons.copy({ size: 16 }) }), document.createTextNode(btnText));
    btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(value); toast(t("guard.copied"), { kind: "good" }); }
      catch { input.select(); }
    });
    return el("div", { class: "input-row", style: "margin-block-start:var(--s2)" }, input, btn);
  }

  function stepItem(n, body, accent = false) {
    return el("li", { style: "display:flex; gap:var(--s3); align-items:start" },
      el("span", { class: "mono", style: `flex:none; width:26px; height:26px; border:var(--border); border-radius:50%; display:grid; place-items:center; font-size:var(--fs-xs); font-weight:600; ${accent ? "background:var(--accent); color:var(--surface)" : "background:var(--surface)"}`, text: String(n) }),
      body);
  }

  function label(text) { return el("div", { style: "font-weight:600; font-size:var(--fs-sm)", text }); }

  function badge(text, kind = "") {
    const color = kind === "good" ? "var(--tag-safe-ink, var(--ink))" : kind === "bad" ? "var(--tag-fake-ink, var(--ink))" : "var(--ink)";
    return el("span", { class: "mono", style: `border:var(--border); border-radius:999px; padding:1px var(--s2); font-size:var(--fs-xs); color:${color}; background:var(--surface)`, text });
  }

  function stat(num, labelText, big) {
    return el("div", { class: "stat" },
      el("span", { class: big ? "stat-num ltr" : "stat-label", style: big ? "color:var(--tag-fake-ink)" : "font-weight:600; color:var(--ink)", text: num }),
      el("span", { class: "stat-label", text: labelText }));
  }
}
