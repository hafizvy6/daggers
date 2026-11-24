/* ============================================================
   Daggers · api.js — the SINGLE swap point (fixtures ↔ backend)
   · window.API_BASE from config.js  ("" = same origin)
   · DEMO: ?mode=demo | /api/mode down | window.DAGGERS_DEMO
   · SSE: event "finding" (Finding) · "heartbeat" (Status)
   · network-first with last-good cache; fixtures are the floor
   ============================================================ */

import { t } from "./i18n/i18n.js";

const FIXTURE_ROOT = new URL("../fixtures/", import.meta.url).href;
const EVIDENCE_ROOT = new URL("../evidence/", import.meta.url).href;
const CACHE_PREFIX = "daggers.api.v3:";

export const state = {
  demo: false,          // fixtures only (offline story)
  apiDown: false,       // live requested, unreachable → saved data
  offline: !navigator.onLine,
  mode: "live",         // banner/mode chip
};

const listeners = new Set();
export function onState(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit() { listeners.forEach((fn) => fn(state)); }

export function apiBase() {
  const b = (typeof window !== "undefined" && window.API_BASE) || "";
  return b.replace(/\/$/, "");
}
const url = (p) => `${apiBase()}${p}`;

/* ---------------- boot: decide demo vs live ----------------------- */
export async function initApi() {
  const q = new URLSearchParams(location.search);
  if (q.get("mode") === "demo" || window.DAGGERS_DEMO === true) {
    state.demo = true; state.mode = "demo"; emit(); return state;
  }
  try {
    const res = await fetchWithTimeout(url("/api/status"), {}, 3000);
    if (!res.ok) throw new Error(String(res.status));
    const st = await res.json();
    state.mode = st.mode === "demo" ? "demo" : "live";
    state.demo = state.mode === "demo";
    state.apiDown = false;
  } catch {
    // Two different truths, and the banner must not lie about which one it is:
    //  · no API_BASE configured  → this is a static deploy, saved evidence (DEMO)
    //  · API_BASE set but down   → service unreachable, running on last-good (SAVED)
    state.apiDown = apiBase() !== "";
    state.demo = !state.apiDown;
    state.mode = state.apiDown ? "saved" : "demo";
  }
  emit();
  return state;
}

export function setDemo(on) {
  state.demo = on;
  state.mode = on ? "demo" : (state.apiDown ? "saved" : "live");
  emit();
  window.dispatchEvent(new CustomEvent("daggers:mode", { detail: { mode: state.mode } }));
}

export function watchNetwork() {
  const set = () => { state.offline = !navigator.onLine; emit(); };
  window.addEventListener("online", set);
  window.addEventListener("offline", set);
}

/* ---------------- core fetch: live → cache → fixtures ------------- */
function fetchWithTimeout(resource, opts = {}, ms = 7000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  return fetch(resource, { credentials: "omit", ...opts, signal: ctl.signal })
    .finally(() => clearTimeout(timer));
}

const cacheKey = (k) => `${CACHE_PREFIX}${k}`;
function cacheGet(k) { try { const v = localStorage.getItem(cacheKey(k)); return v ? JSON.parse(v) : null; } catch { return null; } }
function cacheSet(k, v) { try { localStorage.setItem(cacheKey(k), JSON.stringify(v)); } catch { /* quota */ } }

async function fixture(path) {
  const res = await fetch(new URL(path, FIXTURE_ROOT), { cache: "no-cache" });
  if (!res.ok) throw new Error(`fixture ${path}: ${res.status}`);
  return res.json();
}

/**
 * GET with the demo ladder. `paths` = [liveApiPath, fixturePath, cacheKey?]
 */
async function get({ path, fixturePath, cacheName, timeout = 7000 }) {
  const key = cacheName || path;
  if (state.demo) return freshen(await fixture(fixturePath));
  try {
    const res = await fetchWithTimeout(url(path), {}, timeout);
    if (!res.ok) throw new Error(String(res.status));
    const data = await res.json();
    if (data && typeof data === "object") cacheSet(key, data);
    return data;
  } catch {
    if (!state.apiDown) { state.apiDown = true; emit(); }
    const hit = cacheGet(key);
    if (hit) return freshen(hit);
    return freshen(await fixture(fixturePath));
  }
}

/* Demo timestamps: fixtures carry *age_min offsets* so the story is
   always "minutes ago". Re-anchor ISO fields against the real clock. */
export function freshen(data) {
  if (!data || typeof data !== "object") return data;
  const now = Date.now();
  const fix = (obj) => {
    if (!obj || typeof obj !== "object") return obj;
    if (typeof obj.age_min === "number" && obj.first_seen) {
      obj.first_seen = new Date(now - obj.age_min * 60000).toISOString();
    }
    if (typeof obj.cert_age_min === "number" && obj.cert_issued) {
      obj.cert_issued = new Date(now - obj.cert_age_min * 60000).toISOString();
    }
    if (typeof obj.filed_age_min === "number" && obj.filed_at) {
      obj.filed_at = new Date(now - obj.filed_age_min * 60000).toISOString();
    }
    return obj;
  };
  if (Array.isArray(data)) { data.forEach(fix); return data; }
  fix(data);
  for (const k of ["findings", "reports", "results", "scans", "numbers"]) {
    if (Array.isArray(data[k])) data[k].forEach(fix);
  }
  if (data.evidence) fix(data.evidence);
  return data;
}

/* ---------------- contract C1/C2/C3/C4 methods -------------------- */

export async function getFeed() {
  const data = await get({ path: "/api/feed", fixturePath: "feed.json", cacheName: "feed" });
  const findings = Array.isArray(data) ? data : (data.findings || []);
  return findings.map(withEvidenceUrl);
}

export async function getFinding(id) {
  try {
    return withEvidenceUrl(await get({
      path: `/api/finding/${id}`, fixturePath: `finding_${id}.json`, cacheName: `finding:${id}`,
    }));
  } catch {
    return null;
  }
}

export async function getReports() {
  const data = await get({ path: "/api/reports", fixturePath: "reports.json", cacheName: "reports" });
  const reports = Array.isArray(data) ? data : (data.reports || []);
  reports.forEach((r) => { if (r.evidence) withEvidenceUrl(r.evidence); });
  return reports;
}

export async function fileReport(findingId) {
  if (state.demo) {
    const reports = (cacheGet("reports")?.reports) || (await fixture("reports.json")).reports;
    const findings = (cacheGet("feed")?.findings) || (await fixture("feed.json")).findings;
    const ev = findings.find((f) => f.id === findingId) || null;
    const existing = reports.find((r) => r.finding_id === findingId);
    if (existing) return existing;
    const r = {
      id: Math.max(...reports.map((x) => x.id), 0) + 1,
      finding_id: findingId, domain: ev?.domain, status: "QUEUED", auto: false,
      filed_at: new Date().toISOString(), blocked_hits: 0, channel: "web", evidence: ev,
    };
    reports.unshift(r);
    cacheSet("reports", { reports });
    return freshen(r);
  }
  const res = await fetchWithTimeout(url("/api/reports"), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId }),
  }, 9000);
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

export async function advanceReport(id, to) {
  if (state.demo) {
    const saved = cacheGet("reports") || (await fixture("reports.json"));
    const r = saved.reports.find((x) => x.id === id);
    if (r) { r.status = to; cacheSet("reports", saved); }
    return r;
  }
  const res = await fetchWithTimeout(url(`/api/reports/${id}/advance`), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: to }),
  }, 9000);
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

export async function scan(input, kind) {
  if (state.demo) {
    const { scans } = await fixture("scan.json");
    const needle = String(input).toLowerCase();
    const hit = scans.find((s) =>
      needle.includes(s.input.toLowerCase()) ||
      s.input.toLowerCase().includes(needle) ||
      (kind === "number" && needle.replace(/\D/g, "") === s.input.replace(/\D/g, "")));
    if (hit) return scanResult(hit);
    return scanResult(heuristicScan(input, kind, await rules()));
  }
  try {
    const res = await fetchWithTimeout(url("/api/scan"), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(kind ? { [kind]: input } : { input }),
    }, 9000);
    if (!res.ok) throw new Error(String(res.status));
    const data = await res.json();
    cacheSet(`scan:${needle(input)}`, data);
    return scanResult(data);
  } catch {
    const saved = cacheGet(`scan:${needle(input)}`);
    if (saved) return scanResult(saved);
    const { scans } = await fixture("scan.json");
    const nInput = String(input).toLowerCase();
    const local = scans.find((s) => nInput.includes(s.input.toLowerCase()) || s.input.toLowerCase().includes(nInput));
    return scanResult(local || heuristicScan(input, kind, await rules()));
  }
}
const needle = (s) => String(s).slice(0, 120).replace(/\W+/g, "-");

function scanResult(r) {
  const out = { ...r };
  if (out.finding_id && !out.evidence_url) out.evidence_url = evidenceUrl(out.finding_id);
  return out;
}

/* Offline rules tier — a deliberately simple, honest fallback that mirrors the
   shape of core/ output. Pattern data lives in fixtures/offline_rules.json so the
   rules can be changed without touching code; the wording is i18n (offline.*). */
let offlineRules = null;
async function rules() {
  if (offlineRules) return offlineRules;
  try {
    offlineRules = cacheGet("offline_rules") || (await fixture("offline_rules.json"));
    cacheSet("offline_rules", offlineRules);
  } catch {
    // absolute last resort: no rules file on the device at all
    offlineRules = { premium_prefixes: [], risky_tlds: [], lure_keywords: [],
                     brand_tokens: [], official_domains: [], weights: {} };
  }
  return offlineRules;
}

function heuristicScan(input, kind, R) {
  const text = String(input || "").trim();
  const isNumber = kind === "number" || /^\+?[\d\s\-()]{7,}$/.test(text);
  const w = R.weights || {};

  if (isNumber) {
    const digits = text.replace(/\D/g, "");
    if (R.premium_prefixes.some((pre) => digits.startsWith(pre))) {
      return {
        kind: "number", input: text, verdict: "MALICIOUS", score: w.premium ?? 0.74,
        reasons: [t("offline.premiumRange"), t("offline.premiumBait")],
        scam_type: "premium-rate", offline_capable: true,
      };
    }
    return {
      kind: "number", input: text, verdict: "UNKNOWN", score: 0,
      reasons: [t("offline.numberUnknown")], offline_capable: true,
    };
  }

  const m = text.match(/https?:\/\/[^\s]+/i);
  const host = (m ? m[0] : text).replace(/^https?:\/\//i, "").split(/[/?#]/)[0].toLowerCase();
  const tld = host.split(".").pop() || "";
  const hasRiskyTld = R.risky_tlds.includes(tld);
  const hasLure = R.lure_keywords.some((k) => host.includes(k));
  const hasBrand = R.brand_tokens.some((b) => host.includes(b));
  const isOfficial = R.official_domains.some((d) => host === d || host.endsWith(`.${d}`));

  if (isOfficial) {
    return {
      kind: "url", input: text, verdict: "SAFE", score: 0.02,
      reasons: [t("offline.officialMatch")], offline_capable: true,
    };
  }

  const score = Math.min(0.95, (hasBrand ? (w.brand ?? 0.45) : 0)
    + (hasRiskyTld ? (w.risky_tld ?? 0.2) : 0)
    + (hasLure ? (w.lure ?? 0.2) : 0));
  const verdict = score >= 0.65 ? "MALICIOUS" : score >= 0.35 ? "SUSPICIOUS" : "UNKNOWN";
  const reasons = [];
  if (hasBrand) reasons.push(t("offline.brandOnForeign"));
  if (hasRiskyTld) reasons.push(t("offline.riskyTld"));
  if (hasLure) reasons.push(t("offline.lureKeyword"));
  if (!reasons.length) reasons.push(t("offline.noSigns"));
  return { kind: "url", input: text, verdict, score, reasons, offline_capable: true };
}

/** Contract C3: a SweepRun is *created* (POST) then fetched by id (GET /api/sweep/{id}). */
export async function getSweep(channel = "web", query) {
  const fixturePath = channel === "maps" ? "sweep_maps.json" : "sweep_web.json";
  const cacheName = `sweep:${channel}`;

  if (state.demo) return withSweepUrls(freshen(await fixture(fixturePath)));

  try {
    const res = await fetchWithTimeout(url("/api/sweep"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel, query }),
    }, 7000);
    if (!res.ok) throw new Error(String(res.status));
    const run = await res.json();
    cacheSet(cacheName, run);
    return withSweepUrls(freshen(run));
  } catch {
    if (!state.apiDown) { state.apiDown = true; emit(); }
    const hit = cacheGet(cacheName);
    return withSweepUrls(freshen(hit || (await fixture(fixturePath))));
  }
}

function withSweepUrls(run) {
  run?.results?.forEach(withEvidenceUrl);
  return run;
}

export async function getGuardStats() {
  return get({ path: "/api/guard/stats", fixturePath: "guard_stats.json", cacheName: "guard:stats" });
}

/** Sample inputs for the Checker / Numbers / Sweep pills (fixtures/examples.json). */
export async function getExamples() {
  const data = await get({ path: "/api/examples", fixturePath: "examples.json", cacheName: "examples" });
  return data;
}

export async function getStatus() {
  return get({ path: "/api/status", fixturePath: "status.json", cacheName: "status" });
}

/* ---------------- AI (WS3 provides) -------------------------------- */

/**
 * POST /api/report/{id}/analysis → SSE text deltas.
 * onDelta(text) · returns final {summary_en, summary_ar, provider, fallback}.
 * Demo/offline: streams the stored case char-by-char (identical UI).
 */
export async function streamAnalysis(reportId, { onDelta, signal } = {}) {
  const id = String(reportId);
  if (!state.demo && !state.apiDown) {
    try {
      return await streamSSE(url(`/api/report/${id}/analysis`), { onDelta, signal });
    } catch (err) {
      if (err?.name === "AbortError") throw err;
      // fall through to template — badge appears, demo never dies
    }
  }
  const cases = await fixture("ai_cases.json");
  const c = cases[id] || cases[Object.keys(cases)[0]];
  return streamText(c.summary_en, onDelta, signal, {
    summary_en: c.summary_en, summary_ar: c.summary_ar,
    provider: "template", fallback: true,
  });
}

async function streamSSE(endpoint, { onDelta, signal }) {
  const res = await fetchWithTimeout(endpoint, {
    method: "POST", headers: { Accept: "text/event-stream" }, signal,
  }, 30000);
  if (!res.ok || !res.body) throw new Error(String(res.status));
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  let final = null;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const frames = buf.split("\n\n");
    buf = frames.pop() || "";
    for (const frame of frames) {
      const lines = frame.split("\n");
      let event = "message", data = "";
      for (const line of lines) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (!data) continue;
      let payload; try { payload = JSON.parse(data); } catch { payload = { delta_text: data }; }
      if (event === "delta" || payload.delta_text) onDelta?.(payload.delta_text ?? "");
      if (event === "final" || payload.summary_en) final = payload;
    }
  }
  if (!final) throw new Error("stream ended without final event");
  return final;
}

export function streamText(text, onDelta, signal, final) {
  return new Promise((resolve, reject) => {
    let i = 0;
    const step = () => {
      if (signal?.aborted) return reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
      const chunk = text.slice(i, i + 3);
      i += 3;
      if (chunk) onDelta?.(chunk);
      if (i >= text.length) {
        setTimeout(() => resolve(final), 120);
        return;
      }
      setTimeout(step, 14);
    };
    step();
  });
}

export async function getTakedown(reportId) {
  if (!state.demo && !state.apiDown) {
    try {
      const res = await fetchWithTimeout(url(`/api/report/${reportId}/takedown`), { method: "POST" }, 25000);
      if (!res.ok) throw new Error(String(res.status));
      return res.json();
    } catch { /* fall through */ }
  }
  const t = await fixture("takedowns.json");
  const hit = t[String(reportId)];
  if (hit) return hit;
  // No canned letter last: compose one from the report + a localized template.
  const reports = await getReports();
  const r = reports.find((x) => String(x.id) === String(reportId));
  const domain = r?.domain || t("letter.unknownDomain");
  const ev = r?.evidence || {};
  const reasons = (ev.reasons || []).slice(0, 4).map((x) => `  - ${x}`).join("\n");
  return { letter_en: t("letter.template", { domain, reasons: reasons || `  - ${t("letter.unknownReason")}` }) };
}

/* ---------------- SSE: live feed + heartbeat ----------------------- */
export function connectStream({ onFinding, onHeartbeat } = {}) {
  if (state.demo || state.apiDown) {
    return { demo: true, close() {}, inject: async (finding) => {
      onFinding?.(withEvidenceUrl(freshFinding(finding)));
    } };
  }
  let es;
  try {
    es = new EventSource(url("/api/stream"));
  } catch { return { demo: true, close() {}, inject() {} }; }
  let opened = false;
  es.addEventListener("open", () => { opened = true; });
  es.addEventListener("finding", (e) => {
    try { onFinding?.(withEvidenceUrl(JSON.parse(e.data))); } catch { /* ignore */ }
  });
  es.addEventListener("heartbeat", (e) => {
    try { onHeartbeat?.(JSON.parse(e.data)); } catch { /* ignore */ }
  });
  es.addEventListener("error", () => { if (!opened) es.close(); });
  return { demo: false, close: () => es.close(), inject() {} };
}

export async function getStreamDemo() {
  return fixture("stream_demo.json");
}

/** DEMO_MODE only: lands the scripted finding in the saved feed + reports. */
export async function injectDemoBeat() {
  const demo = await getStreamDemo();
  const feed = cacheGet("feed") || (await fixture("feed.json"));
  const findings = feed.findings || feed;
  if (!findings.some((f) => f.id === demo.finding.id)) findings.unshift(demo.finding);
  cacheSet("feed", { findings, count: findings.length });

  const reports = cacheGet("reports") || (await fixture("reports.json"));
  if (!reports.reports.some((r) => r.finding_id === demo.finding.id)) {
    const r = { ...demo.report, evidence: demo.finding };
    reports.reports.unshift(r);
    cacheSet("reports", reports);
  }
  return withEvidenceUrl(freshFinding(demo.finding));
}

function freshFinding(f) {
  if (!f) return f;
  return freshen({ ...f });
}

/* ---------------- evidence helpers -------------------------------- */
export function evidenceUrl(finding) {
  const f = typeof finding === "object" ? finding : null;
  if (f?.evidence_url) {
    if (/^https?:/.test(f.evidence_url)) return f.evidence_url;
    const base = apiBase();
    return base ? `${base}${f.evidence_url}` : f.evidence_url;
  }
  if (f?.id) return new URL(`${f.id}.jpg`, EVIDENCE_ROOT).href;
  return null;
}
export function withEvidenceUrl(f) {
  if (f && typeof f === "object") f.evidence_url = evidenceUrl(f);
  return f;
}

/* verdict → tag */
export const VERDICT_TAG = {
  MALICIOUS: "fake", SUSPICIOUS: "warning", MISLEADING: "misleading",
  SAFE: "safe", UNKNOWN: "unknown", QUEUED: "warning",
};
export const tagFor = (verdict) => VERDICT_TAG[String(verdict || "").toUpperCase()] || "unknown";
