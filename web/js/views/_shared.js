/* Daggers · small view helpers (headers, cards, labels) */
import { el } from "../components/tag.js";
import { t } from "../i18n/i18n.js";

export function pageHead({ kicker, title, subtitle, actions = [] }) {
  const head = el("header", { class: "page-head" });
  const left = el("div");
  if (kicker) left.append(el("div", { class: "page-kicker", text: kicker }));
  left.append(el("h1", { text: title }));
  if (subtitle) left.append(el("p", { class: "muted", style: "margin:var(--s2) 0 0; max-width:62ch", text: subtitle }));
  head.append(left);
  if (actions.length) head.append(el("div", { class: "row" }, ...actions));
  return head;
}

export function card(title, kicker = "", ...body) {
  const c = el("section", { class: "card" });
  if (title) {
    const h = el("div", { class: "card-title" }, el("span", { text: title }));
    if (kicker) h.append(el("span", { class: "card-kicker", text: kicker }));
    c.append(h);
  }
  c.append(...body);
  return c;
}

export function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const pair of pairs) {
    if (!pair) continue;
    const [k, v] = pair;
    if (v == null || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v)));
  }
  return dl;
}

export function stack(...children) { return el("div", { class: "stack" }, ...children); }
export function row(...children) { return el("div", { class: "row" }, ...children); }
export { el };

/** Card shown when the backend answers 401/403 for investigative data. */
export function authGate(err) {
  const forbidden = err?.status === 403;
  return el("section", { class: "card" },
    el("div", { class: "card-title" }, el("span", { text: t(forbidden ? "auth.forbiddenTitle" : "auth.requiredTitle") })),
    el("p", { text: t(forbidden ? "auth.forbiddenBody" : "auth.requiredBody") }),
    forbidden ? null : el("a", { class: "btn btn-primary", href: `#/login/${location.hash.replace(/^#\/?/, "")}`, text: t("auth.signIn") }));
}
