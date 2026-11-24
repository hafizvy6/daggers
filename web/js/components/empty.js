/* Daggers · empty / error states — friendly, never scary */
import { el } from "./tag.js";
import { mascot } from "./icons.js";

export function emptyState({ title, body, mood = "calm", action = null }) {
  const node = el("div", { class: "empty" },
    el("div", { class: "empty-art", html: mascot({ mood }) }),
    el("div", { class: "empty-title", text: title }),
    body ? el("p", { text: body }) : null,
  );
  if (action) node.append(action);
  return node;
}

export function errorCard({ title, body, retry = null, retryLabel = "" }) {
  const node = el("div", { class: "card", style: "border-color: var(--butter); background: var(--butter-tint); color: var(--butter-ink)" },
    el("div", { class: "card-title", text: `⚑ ${title}` }),
    el("p", { text: body }),
  );
  if (retry) {
    const b = el("button", { class: "btn btn-sm", text: retryLabel });
    b.addEventListener("click", retry);
    node.append(b);
  }
  return node;
}
