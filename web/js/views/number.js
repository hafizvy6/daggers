/* Daggers · Number check — before you answer (plan Scenario 8). Offline rules. */
import { t, reasonsOf } from "../i18n/i18n.js";
import { scan, tagFor, getExamples } from "../api.js";
import { el, tagChip, reasonChip } from "../components/tag.js";
import { emptyState } from "../components/empty.js";
import { pageHead, card } from "./_shared.js";
import { icons } from "../components/icons.js";

export default async function NumberView() {
  const root = el("div");
  root.append(pageHead({
    kicker: t("number.kicker"), title: t("number.title"), subtitle: t("number.subtitle"),
    actions: [el("a", { class: "btn btn-sm", href: "#/check" }, el("span", { html: icons.check({ size: 16 }) }), document.createTextNode(t("check.kicker")))],
  }));
  const wrap = el("div", { class: "stack" });
  root.append(wrap);

  const input = el("input", {
    class: "input", dir: "ltr", type: "tel", inputmode: "tel",
    placeholder: t("number.placeholder"), "aria-label": t("number.inputLabel"), autocomplete: "off",
  });
  input.id = "numberInput";
  const btn = el("button", { class: "btn btn-primary btn-lg", type: "submit" },
    el("span", { html: icons.phone({ size: 18 }) }), el("span", { text: t("number.btn") }));
  const form = el("form", { class: "stack", style: "gap:var(--s3)" });
  form.append(el("div", { class: "field" },
    el("label", { for: "numberInput", text: t("number.inputLabel") }),
    el("div", { class: "input-row" }, input, btn)));
  const exRow = el("div", { class: "pill-row", hidden: true },
    el("span", { class: "muted", style: "font-size:var(--fs-xs); align-self:center", text: t("number.examplesTitle") }));
  getExamples().then((ex) => {
    const numbers = Array.isArray(ex.numbers) ? ex.numbers : [];
    numbers.forEach((number) => {
      const b = el("button", { type: "button", class: "query-pill mono ltr", text: number });
      b.addEventListener("click", () => { input.value = number; input.focus(); });
      exRow.append(b);
    });
    exRow.hidden = numbers.length === 0;
  }).catch(() => { exRow.hidden = true; });
  form.append(exRow);

  const verdictHost = el("div");
  const honest = card(t("number.honestTitle"), "", el("p", { style: "font-size:var(--fs-sm)", text: t("number.honestBody") }));
  honest.style.background = "var(--paper)";
  const honestWrap = el("div", { class: "grid-2", style: "align-items:start" }, verdictHost, honest);
  wrap.append(card(null, "", form), honestWrap);
  verdictHost.append(emptyState({ title: t("number.cleanTitle"), body: t("number.sourceNote"), mood: "calm" }));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (!v) return input.focus();
    btn.disabled = true;
    const res = await scan(v, "number").catch(() => null);
    btn.disabled = false;
    if (!res) {
      verdictHost.replaceChildren(el("div", { class: "note" }, el("span", { text: "⚑" }), el("span", { text: t("number.error") })));
      return;
    }
    verdictHost.replaceChildren(numberCard(res));
  });

  return root;
}

function numberCard(res) {
  const tagKey = tagFor(res.verdict, res);
  const c = el("section", { class: "card" });
  const titleKey = tagKey === "safe" ? "number.cleanTitle" : tagKey === "unknown" ? "number.cleanTitle" : "number.knownTitle";
  c.append(el("div", { class: "row", style: "justify-content:space-between" },
    tagChip(tagKey, { size: "lg" }),
    el("span", { class: "muted", style: "font-size:var(--fs-xs)", text: res.label || "" })));
  c.append(el("div", { class: "vh-domain", text: res.number || res.input }));
  c.append(el("div", { style: "font-weight:600; margin-block-start:var(--s2)", text: t(titleKey) }));
  if (tagKey === "safe" || tagKey === "unknown") {
    c.append(el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("number.cleanBody") }));
  }
  if (reasonsOf(res).length) c.append(el("div", { class: "chips", style: "margin-block-start:var(--s3)" }, ...reasonsOf(res).map(reasonChip)));
  c.append(el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s3)", text: t("number.sourceNote") }));
  return c;
}
