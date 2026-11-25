/* Daggers Shield service worker: the only place that talks to the backend.
 * - Sends only the sanitized result URL (no query string, no search terms, no page content).
 * - Caches in chrome.storage.session (memory only, cleared when the browser closes).
 * - Failures are cached briefly as errors and displayed as NOT CHECKED — never SAFE.
 */
importScripts("lib/core.js");
const Core = self.DaggersCore;
const MAX_CONCURRENT = 4;
let active = 0;
const queue = [];

async function settings() {
  const stored = await chrome.storage.sync.get({ apiBase: Core.DEFAULT_API_BASE, enabled: true });
  return { apiBase: Core.validateApiBase(stored.apiBase) || Core.DEFAULT_API_BASE, enabled: stored.enabled !== false };
}

function cacheKey(url) { return "c:" + url; }

async function cacheGet(url) {
  try {
    const key = cacheKey(url);
    const item = (await chrome.storage.session.get(key))[key];
    if (!item) return null;
    const ttl = item.value && item.value.error ? Core.NEGATIVE_TTL_MS : Core.CACHE_TTL_MS;
    if (Date.now() - item.at > ttl) { await chrome.storage.session.remove(key); return null; }
    return item.value;
  } catch (_) { return null; }
}

async function cachePut(url, value) {
  try { await chrome.storage.session.set({ [cacheKey(url)]: { at: Date.now(), value } }); } catch (_) { /* quota: skip cache */ }
}

function withSlot(task) {
  return new Promise((resolve) => {
    const run = async () => {
      active++;
      try { resolve(await task()); } finally { active--; const next = queue.shift(); if (next) next(); }
    };
    if (active < MAX_CONCURRENT) run(); else queue.push(run);
  });
}

async function checkOne(url, lang, apiBase) {
  const cached = await cacheGet(url);
  if (cached) return cached;
  return withSlot(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Core.REQUEST_TIMEOUT_MS);
    let value;
    try {
      const resp = await fetch(apiBase + "/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "url", input: url, lang: lang === "ar" ? "ar" : "en" }),
        signal: controller.signal,
        credentials: "omit",
        cache: "no-store"
      });
      value = resp.ok ? Core.pickFields(await resp.json()) : { error: "http_" + resp.status };
    } catch (e) {
      value = { error: e && e.name === "AbortError" ? "timeout" : "network" };
    } finally {
      clearTimeout(timer);
    }
    // Only real answers are cached: a failure is retried next time (it shows NOT CHECKED, never SAFE).
    if (!value.error) await cachePut(url, value);
    return value;
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "check" && Array.isArray(msg.urls) && sender.tab) {
    (async () => {
      const cfg = await settings();
      if (!cfg.enabled) { sendResponse({ disabled: true, results: {} }); return; }
      const urls = msg.urls.map(Core.sanitizeResultUrl).filter(Boolean).slice(0, 30);
      const results = {};
      await Promise.all(urls.map(async (u) => { results[u] = await checkOne(u, msg.lang, cfg.apiBase); }));
      sendResponse({ results });
    })();
    return true;
  }
  if (msg.type === "health") {
    (async () => {
      const cfg = await settings();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Core.REQUEST_TIMEOUT_MS);
      try {
        const resp = await fetch(cfg.apiBase + "/api/healthz", { signal: controller.signal, credentials: "omit" });
        sendResponse({ ok: resp.ok, apiBase: cfg.apiBase });
      } catch (_) {
        sendResponse({ ok: false, apiBase: cfg.apiBase });
      } finally { clearTimeout(timer); }
    })();
    return true;
  }
  if (msg.type === "clearCache") {
    chrome.storage.session.clear().then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
