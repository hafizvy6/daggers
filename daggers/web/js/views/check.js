/* Daggers · Check — paste / share-target landing (plan Scenarios 3, 9, 11).
   Instant verdict card + proof + offline note. */
import { t, reasonsOf } from "../i18n/i18n.js";
import { scan, state, tagFor, getExamples } from "../api.js";
import { el, tagChip, chip, reasonChip } from "../components/tag.js";
import { emptyState } from "../components/empty.js";
import { pageHead, card, stack } from "./_shared.js";
import { icons } from "../components/icons.js";
import { evidenceFrame } from "../components/evidence.js";
import { toastFiled } from "../components/toast.js";

export default async function Check(ctx) {
  const root = el("div");
  root.append(pageHead({
    kicker: t("check.kicker"), title: t("check.title"), subtitle: t("check.subtitle"),
    actions: [el("a", { class: "btn btn-sm", href: "#/number" }, el("span", { html: icons.phone({ size: 16 }) }), document.createTextNode(t("check.numberLink")))],
  }));

  const wrap = el("div", { class: "stack" });
  root.append(wrap);

  /* share-target landing */
  const shared = sessionStorage.getItem("daggers:share");
  if (shared) {
    sessionStorage.removeItem("daggers:share");
    const note = el("div", { class: "note note-teal" }, el("span", { text: "↪" }),
      el("span", { class: "grow", text: t("check.shareBanner") }));
    wrap.append(note);
  }

  /* input card */
  const input = el("input", {
    class: "input", dir: "ltr", type: "text", inputmode: "text",
    placeholder: t("check.placeholder"), "aria-label": t("check.inputLabel"),
    autocomplete: "off", spellcheck: "false",
  });
  if (shared) input.value = shared;
  const btn = el("button", { class: "btn btn-primary btn-lg" },
    el("span", { html: icons.check({ size: 20 }) }), document.createTextNode(t("check.btn")));
  const form = el("form", { class: "stack", style: "gap:var(--s3)" });
  const field = el("div", { class: "field" }, el("label", { text: t("check.inputLabel"), for: "checkInput" }), input);
  input.id = "checkInput";
  form.append(field, el("div", { class: "row" }, btn,
    el("span", { class: "field-hint", style: "margin-inline-start:var(--s2)", text: state.offline ? t("check.offlineNote") : "" })));

  // sample inputs are fixture data (web/fixtures/examples.json), labels are i18n keys
  const examples = el("div", { class: "row", style: "margin-block-start:var(--s2)" },
    el("span", { class: "muted", style: "font-size:var(--fs-xs)", text: t("check.examplesTitle") }));
  getExamples().then((ex) => {
    for (const item of ex.check || []) {
      const b = el("button", { type: "button", class: "query-pill", text: t(item.label_key) });
      b.addEventListener("click", () => { input.value = item.payload; input.focus(); });
      examples.append(b);
    }
  }).catch(() => { /* offline with no cache: pills simply don't render */ });
  form.append(examples);

  const verdictHost = el("div");
  wrap.append(card(null, "", form), verdictHost);

  if (state.offline) wrap.prepend(el("div", { class: "note" }, el("span", { text: "⊘" }), el("span", { text: t("check.offlineNote") })));

  verdictHost.append(emptyState({ title: t("check.emptyVerdictTitle"), body: t("check.emptyVerdictBody") }));

  async function run(e) {
    e?.preventDefault();
    const value = input.value.trim();
    if (!value) { input.focus(); return; }
    btn.disabled = true;
    const original = btn.lastChild.textContent;
    btn.lastChild.textContent = t("check.checking");
    const loading = el("div", { class: "card", "aria-hidden": "true" },
      el("div", { class: "sk sk-line w-40" }), el("div", { class: "sk sk-line w-80" }), el("div", { class: "sk sk-line w-60" }));
    verdictHost.replaceChildren(loading);
    try {
      const res = await scan(value);
      verdictHost.replaceChildren(verdictCard(res));
    } catch {
      verdictHost.replaceChildren(el("div", { class: "note" }, el("span", { text: "⚑" }), el("span", { text: t("check.error") })));
    } finally {
      btn.disabled = false;
      btn.lastChild.textContent = original;
    }
  }
  form.addEventListener("submit", run);
  btn.type = "submit";

  if (shared) { setTimeout(run, 240); }
  return root;
}

function verdictCard(res) {
  const tagKey = tagFor(res.verdict);
  const c = el("section", { class: "card", style: `border-color: var(--tag-${tagKey === "unknown" ? "unknown" : tagKey})` });
  const bodyKey = { safe: "check.safeBody", warning: "check.warnBody", misleading: "check.misleadBody", fake: "check.fakeBody", unknown: "check.unknownBody" }[tagKey];
  const doKey = { safe: "check.doSafe", warning: "check.doWarn", misleading: "check.doMislead", fake: "check.doFake", unknown: "check.doUnknown" }[tagKey];

  const head = el("div", { class: "verdict-hero" });
  head.append(
    tagChip(tagKey, { size: "xl" }),
    el("div", { class: "vh-body" },
      el("div", { class: "vh-domain", text: res.input }),
      el("p", { class: "vh-why", text: t(bodyKey) }),
      el("div", { class: "vh-score row" },
        el("div", { class: "score-bar", style: "min-width:180px" },
          el("div", { class: "track" }, el("div", { class: `fill fill-${tagKey}`, style: `--w:${Math.round((res.score || 0) * 100)}%` })),
          el("span", { class: "val ltr", text: (res.score || 0).toFixed(2) }),
        ),
        res.scam_type ? chip(t("common.source"), res.scam_type) : null,
        res.offline_capable && state.offline ? chip(t("common.offlineShort"), t("common.rulesShort")) : null,
      ),
    ),
  );
  c.append(head);

  if (res.reasons?.length) {
    c.append(el("div", { class: "chips", style: "margin-block-start:var(--s3)" }, ...reasonsOf(res).map(reasonChip)));
  }

  const whatToDo = el("div", { class: "note", style: `margin-block-start:var(--s3); ${tagKey === "fake" ? "" : ""}` },
    el("span", { text: "→" }),
    el("span", {}, el("strong", { text: t("check.whatToDo") + ": " }), t(doKey)));
  c.append(whatToDo);

  if (res.evidence_url) {
    c.append(el("div", { style: "margin-block-start:var(--s4)" },
      evidenceFrame({ evidence_url: res.evidence_url, domain: res.input, clone: 97, brand: "ADCB" }, { compact: true })));
    c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s2)", text: t("check.evidenceNote") }));
  }

  if (res.finding_id) {
    const a = el("a", { class: "btn btn-sm", style: "margin-block-start:var(--s3)", href: `#/finding/${res.finding_id}` },
      el("span", { html: icons.arrow({ size: 16 }), class: "fwd-ico" }),
      document.createTextNode(t("check.seeEvidence")));
    a.querySelector(".fwd-ico").classList.add("flip-x");
    c.append(a);
  }
  return c;
}
