/* ============================================================
   Daggers · api.js — the single client for the LIVE backend
   · window.API_BASE from config.js  ("" = same origin)
   · LIVE ONLY: no demo mode, no fixtures, no simulated results. If the backend
     cannot answer, the UI shows an error — it never invents a verdict.
   · SSE: event "finding" (Finding) · "heartbeat" (Status)
   ============================================================ */

import { getLang } from "./i18n/i18n.js";

const CACHE_PREFIX = "daggers.api.v4:";

export const state = {
  user: null,           // {username, role} when signed in to the Police Portal
  apiDown: false,       // backend unreachable
  offline: !navigator.onLine,
  mode: "live",         // the only mode
};

const listeners = new Set();
export function onState(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit() { listeners.forEach((fn) => fn(state)); }

export function apiBase() {
  const b = (typeof window !== "undefined" && window.API_BASE) || "";
  return b.replace(/\/$/, "");
}
const url = (p) => `${apiBase()}${p}`;

/* ---------------- boot -------------------------------------------- */
export async function initApi() {
  try {
    const res = await fetchWithTimeout(url("/api/status"), {}, 4000);
    state.apiDown = !res.ok;
  } catch {
    state.apiDown = true;
  }
  emit();
  return state;
}

export function watchNetwork() {
  const set = () => { state.offline = !navigator.onLine; emit(); };
  window.addEventListener("online", set);
  window.addEventListener("offline", set);
}

/* ---------------- core fetch ------------------------------------- */
/* Session: HttpOnly SameSite=Strict cookie (same-origin portal) + CSRF header on writes. */
let csrfToken = null;
export class AuthError extends Error {
  constructor(status) { super(`auth ${status}`); this.name = "AuthError"; this.status = status; }
}

function fetchWithTimeout(resource, opts = {}, ms = 7000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  const method = (opts.method || "GET").toUpperCase();
  const headers = { ...(opts.headers || {}) };
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const signal = opts.signal || ctl.signal;
  return fetch(resource, { credentials: "same-origin", ...opts, headers, signal })
    .finally(() => clearTimeout(timer));
}

async function send(path, { method = "POST", body, timeout = 9000 } = {}) {
  const res = await fetchWithTimeout(url(path), {
    method, headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }, timeout);
  if (res.status === 401 || res.status === 403) throw new AuthError(res.status);
  if (!res.ok) {
    let detail = String(res.status);
    try { detail = (await res.json()).detail || detail; } catch { /* not JSON */ }
    throw Object.assign(new Error(typeof detail === "string" ? detail : JSON.stringify(detail)), { status: res.status });
  }
  return res.status === 204 ? null : res.json();
}

/* ---------------- Police Portal session ---------------------------- */
export async function refreshSession() {
  try {
    const res = await fetchWithTimeout(url("/api/auth/me"), {}, 4000);
    if (!res.ok) { state.user = null; csrfToken = null; return null; }
    const data = await res.json();
    state.user = data.user; csrfToken = data.csrf_token;
  } catch { state.user = null; }
  emit();
  return state.user;
}

export async function login(username, password) {
  const res = await fetchWithTimeout(url("/api/auth/login"), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }, 9000);
  if (res.status === 429) throw Object.assign(new Error("locked"), { status: 429 });
  if (!res.ok) throw Object.assign(new Error("invalid"), { status: res.status });
  const data = await res.json();
  state.user = data.user; csrfToken = data.csrf_token;
  emit();
  return data.user;
}

export async function logout() {
  try { await send("/api/auth/logout"); } catch { /* session already gone */ }
  state.user = null; csrfToken = null;
  clearPrivateCache();
  emit();
}

export const can = (role) => {
  const rank = { viewer: 0, investigator: 1, admin: 2 };
  return !!state.user && rank[state.user.role] >= rank[role];
};

const cacheKey = (k) => `${CACHE_PREFIX}${k}`;
// Investigative data (findings, reports, AI, checks) is never written to device storage.
const PRIVATE_KEYS = /^(reports|finding:|inv|ai|sweep:|check|portal)/;
function cacheGet(k) { try { const v = localStorage.getItem(cacheKey(k)); return v ? JSON.parse(v) : null; } catch { return null; } }
function cacheSet(k, v) {
  if (PRIVATE_KEYS.test(k)) return;
  try { localStorage.setItem(cacheKey(k), JSON.stringify(v)); } catch { /* quota */ }
}
export function clearPrivateCache() {
  try {
    Object.keys(localStorage)
      .filter((k) => k.startsWith("daggers.api.v3:") || k.startsWith("daggers.ai.")
        || (k.startsWith(CACHE_PREFIX) && PRIVATE_KEYS.test(k.slice(CACHE_PREFIX.length))))
      .forEach((k) => localStorage.removeItem(k));
  } catch { /* storage unavailable */ }
}

/** Live GET. Public read views may show the last answer seen when the network drops
    (marked `stale`); nothing is ever substituted with sample data. */
async function get({ path, cacheName, timeout = 8000 }) {
  const key = cacheName || path;
  let res;
  try {
    res = await fetchWithTimeout(url(path), {}, timeout);
  } catch {
    res = null;
  }
  if (res && (res.status === 401 || res.status === 403)) throw new AuthError(res.status);
  if (res && res.ok) {
    if (state.apiDown) { state.apiDown = false; emit(); }
    const data = await res.json();
    if (data && typeof data === "object") cacheSet(key, data);
    return data;
  }
  if (!res && !state.apiDown) { state.apiDown = true; emit(); }
  const hit = cacheGet(key);
  if (hit) return Object.assign(Array.isArray(hit) ? hit : { ...hit }, { stale: true });
  throw Object.assign(new Error(res ? `HTTP ${res.status}` : "network"), { status: res ? res.status : 0 });
}

/* ---------------- contract C1/C2/C3/C4 methods -------------------- */

export async function getFeed() {
  const data = await get({ path: "/api/feed", cacheName: "feed" });
  const findings = Array.isArray(data) ? data : (data.findings || []);
  return findings.map(withEvidenceUrl);
}

export async function getFinding(id) {
  try {
    return withEvidenceUrl(await get({ path: `/api/finding/${id}`, cacheName: `finding:${id}` }));
  } catch (err) {
    if (err instanceof AuthError) throw err;
    return null;
  }
}

export async function getReports() {
  const data = await get({ path: "/api/reports", cacheName: "reports" });
  const reports = Array.isArray(data) ? data : (data.reports || []);
  reports.forEach((r) => { if (r.evidence) withEvidenceUrl(r.evidence); });
  return reports;
}

export async function fileReport(findingId) {
  return send("/api/reports", { body: { finding_id: findingId } });
}

export async function advanceReport(id, to) {
  return send(`/api/reports/${id}/advance`, { body: { status: to } });
}

/* ---------------- Live Checker -------------------------------------
   POST /api/check → the engine runs, the finding is STORED for the Police Portal,
   and the stored finding comes back. One request id per click on "Check it":
   a retry of the same click can never create a second finding. */
export class CheckError extends Error {
  constructor(code, message, status, result = null) {
    super(message || code); this.name = "CheckError"; this.code = code; this.status = status; this.result = result;
  }
}

export function newRequestId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function checkInput(input, requestId) {
  let res;
  try {
    res = await fetchWithTimeout(url("/api/check"), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: String(input), lang: getLang() === "ar" ? "ar" : "en", request_id: requestId }),
    }, 30000);
  } catch (err) {
    if (!state.apiDown) { state.apiDown = true; emit(); }
    throw new CheckError(err?.name === "AbortError" ? "timeout" : "backend_unreachable", "", 0);
  }
  if (state.apiDown) { state.apiDown = false; emit(); }
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  if (res.ok && body && typeof body === "object") return withEvidenceUrl(body);
  const detail = body && body.detail;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    throw new CheckError(detail.code || `http_${res.status}`, detail.message || "", res.status, detail.result || null);
  }
  throw new CheckError(res.status === 422 ? "invalid" : `http_${res.status}`, "", res.status);
}

/** Client-side pre-check only (the backend validates again). Mirrors checker.classify limits. */
export function validateInput(value) {
  const text = String(value || "").trim();
  if (!text) return "empty";
  if (text.length > 4000) return "too_long";
  if (!/\s/.test(text) && /^(javascript|data|file|vbscript):/i.test(text)) return "unsupported_scheme";
  return null;
}

/* ---------------- Police Portal: findings index ---------------------- */
export async function searchFindings(filters = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v !== undefined && v !== null && v !== "") q.set(k, v);
  const data = await send(`/api/portal/findings?${q}`, { method: "GET" });
  data.findings = (data.findings || []).map(withEvidenceUrl);
  return data;
}

/** Sweep: POST creates a persisted run (202, status=running) → poll GET /api/sweep/{id}.
    Requires an investigator session. */
export async function getSweep(channel = "web", query, { onProgress } = {}) {
  const body = { channel, lang: getLang() === "ar" ? "ar" : "en" };
  if (query) body.query = query;
  let run = await send("/api/sweep", { body, timeout: 9000 });
  const deadline = Date.now() + 60000;
  while (run && run.status === "running" && Date.now() < deadline) {
    onProgress?.(run);
    await new Promise((r) => setTimeout(r, 800));
    run = await send(`/api/sweep/${run.id}`, { method: "GET" });
  }
  return withSweepUrls(run);
}

export async function listSweeps() {
  return (await send("/api/sweep", { method: "GET" })).runs || [];
}

/* ---------------- Police Portal: investigations, registry, audit ---- */
export async function investigate(urlValue, pageText) {
  return send("/api/investigations", { body: { url: urlValue, page_text: pageText || null }, timeout: 20000 });
}
export async function getInvestigations() {
  return (await send("/api/investigations", { method: "GET" })).findings || [];
}
export async function getRegistry() {
  return send("/api/registry", { method: "GET" });
}
export async function getGuardSync() {
  return send("/api/guard/sync-status", { method: "GET" });
}
export async function getAudit() {
  return (await send("/api/admin/audit?limit=100", { method: "GET" })).entries || [];
}
export async function getReadiness() {
  return send("/api/readiness", { method: "GET" });
}

function withSweepUrls(run) {
  run?.results?.forEach(withEvidenceUrl);
  return run;
}

export async function getGuardStats() {
  return get({ path: "/api/guard/stats", cacheName: "guard:stats" });
}

/* ---------------- Guard (live) ------------------------------------- */
export async function syncGuard() {
  return send("/api/guard/sync", { timeout: 30000 });
}
/** Guard lookup; live=true also runs the engine on https://<domain>/ (lists it if confirmed FAKE). */
export async function guardCheck(domain, live = false) {
  return send(`/api/guard/check?domain=${encodeURIComponent(domain)}&live=${live ? 1 : 0}`,
    { method: "GET", timeout: 30000 });
}
/** Verdict-page data. hit=true records one anonymous block (no personal data). */
export async function guardVerdict(domain, hit = false) {
  return send(`/api/guard/verdict?domain=${encodeURIComponent(domain)}&hit=${hit ? 1 : 0}`, { method: "GET" });
}
export function absoluteUrl(path) {
  if (/^https?:/.test(path || "")) return path;
  return `${apiBase() || location.origin}${path}`;
}

/** Curated Sweep query presets from the backend (no sample findings). */
export async function getExamples() {
  return get({ path: "/api/examples", cacheName: "examples" });
}

export async function getStatus() {
  return get({ path: "/api/status", cacheName: "status" });
}

/* ---------------- AI (WS3 provides) -------------------------------- */

/**
 * POST /api/report/{id}/analysis → SSE text deltas.
 * onDelta(text) · returns final {summary_en, summary_ar, provider, fallback}.
 * The backend chooses the provider (Gemini → Groq → evidence-only template).
 */
export async function streamAnalysis(reportId, { onDelta, signal } = {}) {
  return streamSSE(url(`/api/report/${String(reportId)}/analysis`), { onDelta, signal });
}

async function streamSSE(endpoint, { onDelta, signal }) {
  const res = await fetchWithTimeout(endpoint, {
    method: "POST", headers: { Accept: "text/event-stream" }, signal,
  }, 30000);
  if (res.status === 401 || res.status === 403) throw new AuthError(res.status);
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

export async function getTakedown(reportId) {
  return send(`/api/report/${reportId}/takedown`, { timeout: 25000 });
}

/* ---------------- SSE: live feed + heartbeat ----------------------- */
export function connectStream({ onFinding, onHeartbeat, onGuard } = {}) {
  let es;
  try {
    es = new EventSource(url("/api/stream"));
  } catch { return { close() {} }; }
  es.addEventListener("finding", (e) => {
    try { onFinding?.(withEvidenceUrl(JSON.parse(e.data))); } catch { /* ignore */ }
  });
  es.addEventListener("heartbeat", (e) => {
    try { onHeartbeat?.(JSON.parse(e.data)); } catch { /* ignore */ }
  });
  es.addEventListener("guard", (e) => {
    try { onGuard?.(JSON.parse(e.data)); } catch { /* ignore */ }
  });
  return { close: () => es.close() };
}

/* ---------------- evidence helpers -------------------------------- */
export function evidenceUrl(finding) {
  const f = typeof finding === "object" ? finding : null;
  if (f?.evidence_url) {
    if (/^https?:/.test(f.evidence_url)) return f.evidence_url;
    const base = apiBase();
    return base ? `${base}${f.evidence_url}` : f.evidence_url;
  }
  return null;
}
export function withEvidenceUrl(f) {
  if (f && typeof f === "object") f.evidence_url = evidenceUrl(f);
  return f;
}

/* ONE verdict system: the backend's `tag` (SAFE | WARNING | MISLEADING | FAKE) is
   authoritative. Legacy objects without a tag are mapped conservatively: an engine
   verdict can never become SAFE in the UI (UNKNOWN → warning). */
export const VERDICT_TAG = { MALICIOUS: "fake", SUSPICIOUS: "warning", MISLEADING: "misleading", UNKNOWN: "warning" };
const TAGS = new Set(["safe", "warning", "misleading", "fake"]);
export function tagFor(x) {
  if (x && typeof x === "object") {
    const tag = String(x.tag || "").toLowerCase();
    if (tag === "safe") {
      // SAFE needs the backend's proof: an authenticated government domain OR an approved legitimate site.
      const a = x.domain_auth;
      return a && (a.authenticated === true || a.legitimate_site === true) ? "safe" : "warning";
    }
    if (TAGS.has(tag)) return tag;
    return VERDICT_TAG[String(x.verdict || "").toUpperCase()] || "warning";
  }
  return VERDICT_TAG[String(x || "").toUpperCase()] || "warning";
}
