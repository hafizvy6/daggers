/* Daggers · toasts — bottom-inline-end, calm, auto-dismiss */
import { t } from "../i18n/i18n.js";
import { el } from "./tag.js";

let host = null;
function hostEl() {
  if (!host) {
    host = el("div", { class: "toast-host", role: "status", "aria-live": "polite" });
    document.body.append(host);
  }
  return host;
}

/** kind: "neutral" | "good" | "bad" */
export function toast(message, { kind = "neutral", tag = "", ms = 4200 } = {}) {
  const node = el("div", { class: `toast${kind === "good" ? " is-good" : kind === "bad" ? " is-bad" : ""}` });
  if (tag) node.append(el("span", { class: "toast-tag", text: tag }));
  node.append(el("span", { class: "grow", text: message }));
  const x = el("button", { class: "toast-x", "aria-label": t("common.close"), text: "✕" });
  x.addEventListener("click", () => node.remove());
  node.append(x);
  hostEl().append(node);
  if (ms) setTimeout(() => node.remove(), ms);
  return node;
}

export const toastFiled = () => toast(t("finding.filedToast"), { kind: "good", tag: t("common.filed"), ms: 5200 });
