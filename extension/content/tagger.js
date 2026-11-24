/* Daggers Shield content script: annotates Google ORGANIC results only.
 * Ads, Maps/local packs and internal Google links are skipped (lib/core.js).
 * Labels are built with textContent only — no HTML from the backend is ever injected.
 */
(function () {
  "use strict";
  const Core = self.DaggersCore;
  if (!Core || window.__daggersShield) return;
  window.__daggersShield = true;

  const lang = (document.documentElement.lang || "").toLowerCase().startsWith("ar") ? "ar" : "en";
  const pending = new Map(); // sanitized url -> [anchor]
  let timer = null;

  function makeTag(label, tooltip) {
    const span = document.createElement("span");
    span.className = "daggers-tag " + label.cls;
    span.textContent = label.text;
    span.title = tooltip;
    span.setAttribute("role", "note");
    span.setAttribute("aria-label", "Daggers: " + label.text);
    return span;
  }

  function placeTag(anchor, span) {
    const old = anchor.parentElement && anchor.parentElement.querySelector(":scope > .daggers-tag");
    if (old) old.remove();
    anchor.insertAdjacentElement("afterend", span);
  }

  function collect() {
    const root = document.getElementById("search") || document.getElementById("rso");
    if (!root) return [];
    const found = [];
    root.querySelectorAll("a[href] h3").forEach((h3) => {
      const anchor = h3.closest("a");
      if (!anchor || anchor.dataset.daggersDone) return;
      const verdict = Core.classifyResultLink(anchor);
      anchor.dataset.daggersDone = "1";
      if (!verdict.ok) return;
      const url = Core.sanitizeResultUrl(anchor.href);
      if (!url) return;
      placeTag(anchor, makeTag({ text: "…", cls: "daggers-tag--pending", title: "Checking…" }, "Daggers is checking this result"));
      if (!pending.has(url)) pending.set(url, []);
      pending.get(url).push(anchor);
      found.push(url);
    });
    return found;
  }

  function apply(url, response) {
    const label = Core.labelFor(response);
    const tooltip = Core.tooltipFor(response, label);
    for (const anchor of pending.get(url) || []) placeTag(anchor, makeTag(label, tooltip));
    pending.delete(url);
  }

  function scan() {
    const urls = collect();
    if (!urls.length) return;
    let answered = false;
    try {
      chrome.runtime.sendMessage({ type: "check", urls, lang }, (reply) => {
        answered = true;
        if (chrome.runtime.lastError || !reply) { urls.forEach((u) => apply(u, { error: "extension" })); return; }
        if (reply.disabled) {
          urls.forEach((u) => (pending.get(u) || []).forEach((a) => { const t = a.parentElement && a.parentElement.querySelector(":scope > .daggers-tag"); if (t) t.remove(); }));
          urls.forEach((u) => pending.delete(u));
          return;
        }
        urls.forEach((u) => apply(u, reply.results ? reply.results[u] : { error: "missing" }));
      });
    } catch (_) {
      urls.forEach((u) => apply(u, { error: "extension" }));
    }
    // Hard stop: if the worker never answers, show NOT CHECKED (never SAFE).
    setTimeout(() => { if (!answered) urls.forEach((u) => pending.has(u) && apply(u, { error: "timeout" })); }, Core.REQUEST_TIMEOUT_MS + 4000);
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(scan, 300);
  }

  scan();
  const target = document.getElementById("rcnt") || document.body;
  new MutationObserver(schedule).observe(target, { childList: true, subtree: true });
})();
