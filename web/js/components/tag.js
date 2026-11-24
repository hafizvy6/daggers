/* Daggers · sticker tags (the four) + mono chips + score bars */
import { t } from "../i18n/i18n.js";

export const TAGS = {
  safe:       { cls: "tag-safe",       dot: "dot-safe",       key: "common.tagSafe",       hint: "common.tagSafeHint" },
  warning:    { cls: "tag-warning",    dot: "dot-warning",    key: "common.tagWarning",    hint: "common.tagWarningHint" },
  misleading: { cls: "tag-misleading", dot: "dot-misleading", key: "common.tagMisleading", hint: "common.tagMisleadingHint" },
  fake:       { cls: "tag-fake",       dot: "dot-fake",       key: "common.tagFake",       hint: "common.tagFakeHint" },
  unknown:    { cls: "tag-unknown",    dot: "dot-unknown",    key: "common.tagUnknown",    hint: "common.tagUnknownHint" },
};

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k === "text") node.textContent = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** Tag chip. size: "", "lg", "xl" */
export function tagChip(tagKey, { size = "", withDot = true } = {}) {
  const meta = TAGS[tagKey] || TAGS.unknown;
  return el("span", {
    class: `tag ${meta.cls}${size ? ` tag-${size}` : ""}`,
    title: t(meta.hint),
    "data-tag": tagKey,
  },
    withDot ? el("span", { class: "tag-dot" }) : null,
    t(meta.key),
  );
}

export function dot(tagKey) {
  const meta = TAGS[tagKey] || TAGS.unknown;
  return el("span", { class: `dot-tag ${meta.dot}`, "aria-hidden": "true" });
}

/** Mono chip, e.g. cert age · source · clone % */
export function chip(key, value) {
  const c = el("span", { class: "chip" });
  if (key) c.append(el("span", { class: "chip-k", text: `${key}` }), " ");
  c.append(el("span", { class: "mono ltr", text: value }));
  return c;
}

export function reasonChip(text) {
  return el("span", { class: "chip chip-reason", text });
}

export function scoreBar(tagKey, score, { showValue = true } = {}) {
  const pct = Math.max(0, Math.min(100, Math.round((score || 0) * 100)));
  const bar = el("div", { class: "score-bar", role: "img", "aria-label": `${t("common.score")} ${score}` });
  bar.append(
    el("div", { class: "track" }, el("div", { class: `fill fill-${tagKey}`, style: `--w:${pct}%` })),
    showValue ? el("span", { class: "val ltr", text: (score ?? 0).toFixed(2) }) : null,
  );
  return bar;
}

export function breakdown(signals = []) {
  const host = el("div", { class: "breakdown" });
  const max = Math.max(...signals.map((s) => s.weight || 0), 0.6);
  for (const s of signals) {
    const pct = Math.min(100, Math.round(((s.weight || 0) / max) * 100));
    host.append(el("div", { class: "bd-row" },
      el("span", { class: "bd-label", title: s.label, text: s.label }),
      el("div", { class: "bd-track" }, el("div", { class: "bd-fill", style: `width:${pct}%` })),
      el("span", { class: "bd-val ltr", text: `+${(s.weight || 0).toFixed(2)}` }),
    ));
  }
  return host;
}
