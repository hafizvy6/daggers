/* Daggers · skeleton loaders (outlined, calm) */
import { el } from "./tag.js";

export function feedSkeleton(rows = 6) {
  const box = el("div", { class: "card flush", "aria-hidden": "true" });
  for (let i = 0; i < rows; i++) {
    box.append(el("div", { class: "sk sk-row", style: `margin:12px 16px; height:40px` }));
  }
  return box;
}

export function cardsSkeleton(n = 3) {
  const box = el("div", { class: "stack", "aria-hidden": "true" });
  for (let i = 0; i < n; i++) box.append(el("div", { class: "card" },
    el("div", { class: "sk sk-line w-60" }),
    el("div", { class: "sk sk-line w-80" }),
    el("div", { class: "sk sk-line w-40" }),
  ));
  return box;
}

export function evidenceSkeleton() {
  return el("div", { class: "evidence-frame", "aria-hidden": "true" },
    el("div", { class: "sk", style: "height:320px; border-radius:0" }));
}
