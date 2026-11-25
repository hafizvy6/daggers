// Node tests for the extension (node --test extension/tests). No browser required.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const vm = require("node:vm");
const Core = require("../lib/core.js");

// Minimal element stand-in: `closest` answers from a set of ancestor selectors.
function el(href, ancestors = []) {
  return { href, closest: (sel) => (ancestors.includes(sel) ? {} : null) };
}

test("organic results are eligible; ads, maps and google links are not", () => {
  assert.equal(Core.classifyResultLink(el("https://site.example/page")).ok, true);
  assert.equal(Core.classifyResultLink(el("https://ad.example/", ["#tads"])).ok, false);
  assert.equal(Core.classifyResultLink(el("https://ad.example/", ["[aria-label='Sponsored']"])).ok, false);
  assert.equal(Core.classifyResultLink(el("https://shop.example/", ["[data-local-attribute]"])).ok, false);
  assert.equal(Core.classifyResultLink(el("https://www.google.com/maps/place/x")).ok, false);
  assert.equal(Core.classifyResultLink(el("https://www.google.ae/search?q=x")).ok, false);
  assert.equal(Core.classifyResultLink(el("https://translate.google.com/")).ok, false);
  assert.equal(Core.classifyResultLink(el("javascript:alert(1)")).ok, false);
  assert.equal(Core.classifyResultLink(null).ok, false);
});

test("sanitizeResultUrl drops query, fragment and credentials", () => {
  assert.equal(Core.sanitizeResultUrl("https://a.example/p?token=secret#x"), "https://a.example/p");
  assert.equal(Core.sanitizeResultUrl("https://u:p@a.example/"), null);
  assert.equal(Core.sanitizeResultUrl("ftp://a.example/"), null);
  assert.equal(Core.sanitizeResultUrl("x".repeat(3000)), null);
});

test("SAFE only when backend says SAFE AND domain is authenticated", () => {
  assert.equal(Core.labelFor({ tag: "SAFE", domain_auth: { authenticated: true } }).text, "SAFE");
  assert.equal(Core.labelFor({ tag: "SAFE", domain_auth: { authenticated: false } }).text, "UNVERIFIED");
  // non-government SAFE path: approved news outlet / verified organisation
  const site = Core.labelFor({ tag: "SAFE", domain_auth: { authenticated: false, legitimate_site: true } });
  assert.equal(site.text, "SAFE");
  assert.match(site.title, /not a government source/);
  const popular = Core.labelFor({ tag: "SAFE", domain_auth: { authenticated: false, legitimate_site: true, status: "REPUTABLE_SITE" } });
  assert.equal(popular.text, "SAFE");
  assert.match(popular.title, /Widely used website/);
  assert.equal(Core.labelFor({ tag: "SAFE" }).text, "UNVERIFIED");
  assert.equal(Core.labelFor({ tag: "FAKE" }).text, "FAKE");
  assert.equal(Core.labelFor({ tag: "MISLEADING" }).text, "MISLEADING");
  assert.equal(Core.labelFor({ tag: "WARNING" }).text, "WARNING");
  assert.equal(Core.labelFor({ tag: "BANANA" }).text, "NOT CHECKED");
});

test("failures and legacy UNKNOWN never produce SAFE", () => {
  for (const r of [null, undefined, {}, { error: "timeout" }, { error: "network" }, { error: "http_500" }, "x"]) {
    assert.notEqual(Core.labelFor(r).text, "SAFE");
    assert.notEqual(Core.labelFor(r).cls, "daggers-tag--safe");
  }
  assert.equal(Core.labelFor({ verdict: "UNKNOWN" }).text, "UNVERIFIED"); // unpatched backend
  assert.equal(Core.labelFor({ verdict: "MALICIOUS" }).text, "FAKE");
});

test("api base validation", () => {
  assert.equal(Core.validateApiBase("http://localhost:8000/x"), "http://localhost:8000");
  assert.equal(Core.validateApiBase("https://daggers.example"), "https://daggers.example");
  assert.equal(Core.validateApiBase("http://daggers.example"), null);
  assert.equal(Core.validateApiBase("https://u:p@daggers.example"), null);
  assert.equal(Core.validateApiBase("javascript:alert(1)"), null);
});

test("pickFields keeps no input echo", () => {
  const out = Core.pickFields({ input: "https://x.example/?t=1", tag: "WARNING", verdict: "UNKNOWN", domain_auth: { authenticated: false, status: "UNLISTED", host: "x" } });
  assert.equal(out.input, undefined);
  assert.deepEqual(out.domain_auth, { authenticated: false, legitimate_site: false, status: "UNLISTED" });
});

// ---- service worker with mocked chrome + fetch
function loadWorker(fetchImpl) {
  const store = {};
  let listener;
  const chrome = {
    storage: {
      sync: { get: async (d) => ({ ...d }), set: async () => {} },
      session: {
        get: async (k) => ({ [k]: store[k] }), set: async (o) => Object.assign(store, o),
        remove: async (k) => { delete store[k]; }, clear: async () => { for (const k in store) delete store[k]; }
      }
    },
    runtime: { onMessage: { addListener: (fn) => { listener = fn; } } }
  };
  const sandbox = { chrome, fetch: fetchImpl, AbortController, setTimeout, clearTimeout, URL, JSON, Promise, Date, console };
  sandbox.self = sandbox;
  sandbox.importScripts = (p) => vm.runInContext(fs.readFileSync(path.join(__dirname, "..", p), "utf8"), sandbox);
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), sandbox);
  const send = (msg) => new Promise((resolve) => listener(msg, { tab: { id: 1 } }, resolve));
  return { send, store, sandbox };
}

test("failed backend request is NOT CHECKED, never SAFE, and only the sanitized URL is sent", async () => {
  const sent = [];
  const w = loadWorker(async (url, init) => { sent.push(JSON.parse(init.body)); throw new TypeError("Failed to fetch"); });
  const reply = await w.send({ type: "check", urls: ["https://a.example/p?q=secret"], lang: "en" });
  const result = reply.results["https://a.example/p"];
  assert.equal(result.error, "network");
  assert.equal(w.sandbox.DaggersCore.labelFor(result).text, "NOT CHECKED");
  assert.deepEqual(sent, [{ kind: "url", input: "https://a.example/p", lang: "en" }]);
});

test("HTTP 500 is NOT CHECKED; success uses backend tag; responses cached", async () => {
  let calls = 0;
  const w = loadWorker(async () => { calls++; return { ok: calls > 1, status: calls > 1 ? 200 : 500, json: async () => ({ tag: "FAKE", verdict: "MALICIOUS", domain_auth: { authenticated: false } }) }; });
  let r = await w.send({ type: "check", urls: ["https://b.example/"] });
  assert.equal(w.sandbox.DaggersCore.labelFor(r.results["https://b.example/"]).text, "NOT CHECKED");
  r = await w.send({ type: "check", urls: ["https://c.example/"] });
  assert.equal(w.sandbox.DaggersCore.labelFor(r.results["https://c.example/"]).text, "FAKE");
  await w.send({ type: "check", urls: ["https://c.example/"] });
  assert.equal(calls, 2); // second lookup served from session cache
});

test("manifest uses minimal permissions and no secrets", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["storage"]);
  for (const p of ["tabs", "history", "webRequest", "cookies", "<all_urls>", "scripting"]) {
    assert.ok(!JSON.stringify(manifest).includes(`"${p}"`), p);
  }
  const all = ["background.js", "lib/core.js", "content/tagger.js", "popup/popup.js"].map((f) => fs.readFileSync(path.join(__dirname, "..", f), "utf8")).join("\n");
  assert.ok(!/api[_-]?key|serper|GOOGLE_PLACES|X-Goog/i.test(all));
  assert.ok(!/innerHTML|eval\(|new Function/.test(all));
});

test("never green on failure, unknown tag or missing proof", () => {
  for (const r of [null, undefined, { error: "network" }, { error: "http_503" }, { tag: "UNKNOWN" },
                   { tag: "safe" }, { tag: "SAFE" }, { tag: "SAFE", domain_auth: null },
                   { tag: "SAFE", domain_auth: { authenticated: "true" } }, { verdict: "UNKNOWN" }, "SAFE"]) {
    assert.notEqual(Core.labelFor(r).cls, "daggers-tag--safe", JSON.stringify(r));
  }
});
