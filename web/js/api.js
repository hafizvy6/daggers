/* ============================================================
   Daggers · api.js — one live backend, no fixture fallback.
   · window.API_BASE from config.js ("" = same origin)
   · network-first GET with a last-good cache of REAL responses
   · POST/SSE are live-only; failure is shown as unavailable
   · empty states come from empty arrays, never invented cases
   ============================================================ */

import { getLang } from "./i18n/i18n.js";

const CACHE_PREFIX = "daggers.live.v4:";

export const state = {
  apiDown: false,       // live service unreachable
  offline: !navigator.onLine,
  mode: "live",         // live | unavailable
  adapters: {},         // readiness flags from /api/healthz
  status: null,         // last /api/status response
};

const listeners = new Set();
export function onState(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit() { listeners.forEach((fn) => fn(state)); }

export function apiBase() {
  const value = (typeof window !== "undefined" && window.API_BASE) || "";
  return String(value).replace(/\/$/, "");
}
const url = (path) => `${apiBase()}${path}`;

function setAvailable() {
  if (!state.apiDown && state.mode === "live") return;
  state.apiDown = false;
  state.mode = "live";
  emit();
}

function setUnavailable() {
  if (state.apiDown && state.mode === "unavailable") return;
  state.apiDown = true;
  state.mode = "unavailable";
  emit();
}

/* ---------------- boot: verify the live service ----------------- */
export async function initApi() {
  try {
    const [health, status] = await Promise.all([
      fetchWithTimeout(url("/api/healthz"), {}, 4000).then(requireOk).then((r) => r.json()),
      fetchWithTimeout(url("/api/status"), {}, 4000).then(requireOk).then((r) => r.json()),
    ]);
    state.adapters = health.adapters || {};
    state.status = status;
    cacheSet("status", status);
    setAvailable();
  } catch {
    state.adapters = {};
    state.status = cacheGet("status");
    setUnavailable();
  }
  emit();
  return state;
}

export const refreshApi = initApi;

export function watchNetwork() {
  const update = () => {
    state.offline = !navigator.onLine;
    emit();
    if (!state.offline) refreshApi();
  };
  window.addEventListener("online", update);
  window.addEventListener("offline", update);
  // Periodic recovery when the backend comes back without a browser network event.
  setInterval(() => { if (state.apiDown || !navigator.onLine) refreshApi(); }, 30000);
}

/* ---------------- core fetch ------------------------------------ */
function fetchWithTimeout(resource, opts = {}, ms = 7000) {
  const controller = new AbortController();
  const external = opts.signal;
  if (external) {
    if (external.aborted) controller.abort();
    else external.addEventListener("abort", () => controller.abort(), { once: true });
  }
  const timer = setTimeout(() => controller.abort(), ms);
  const { signal, ...rest } = opts;
  return fetch(resource, { credentials: "omit", ...rest, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

function requireOk(response) {
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response;
}

const cacheKey = (key) => `${CACHE_PREFIX}${key}`;
function cacheGet(key) {
  try {
    const raw = localStorage.getItem(cacheKey(key));
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function cacheSet(key, value) {
  try { localStorage.setItem(cacheKey(key), JSON.stringify(value)); } catch { /* quota */ }
}
function fallbackValue(fallback) {
  if (typeof fallback === "function") return fallback();
  if (fallback && typeof fallback === "object") return JSON.parse(JSON.stringify(fallback));
  return fallback;
}

async function getJson(path, { cacheName, fallback = null, timeout = 7000 } = {}) {
  try {
    const response = await fetchWithTimeout(url(path), {}, timeout);
    requireOk(response);
    const data = await response.json();
    setAvailable();
    if (cacheName) cacheSet(cacheName, data);
    return data;
  } catch (error) {
    if (error?.name !== "AbortError") setUnavailable();
    const saved = cacheName ? cacheGet(cacheName) : null;
    return saved !== null ? saved : fallbackValue(fallback);
  }
}

async function postJson(path, body, { timeout = 9000, signal } = {}) {
  try {
    const response = await fetchWithTimeout(url(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    }, timeout);
    requireOk(response);
    const data = await response.json();
    setAvailable();
    return data;
  } catch (error) {
    if (error?.name !== "AbortError") setUnavailable();
    throw error;
  }
}

/* ---------------- contract C1/C2/C3/C4 methods -------------------- */

export async function getFeed() {
  const data = await getJson("/api/feed", { cacheName: "feed", fallback: [] });
  const findings = Array.isArray(data) ? data : (data.findings || []);
  return findings.map(withEvidenceUrl);
}

export async function getFinding(id) {
  try {
    const response = await fetchWithTimeout(url(`/api/finding/${id}`), {}, 7000);
    if (response.status === 404) { setAvailable(); return null; }
    requireOk(response);
    const data = await response.json();
    setAvailable();
    cacheSet(`finding:${id}`, data);
    return withEvidenceUrl(data);
  } catch {
    setUnavailable();
    const saved = cacheGet(`finding:${id}`);
    return saved ? withEvidenceUrl(saved) : null;
  }
}

export async function getReports() {
  const data = await getJson("/api/reports", { cacheName: "reports", fallback: { reports: [] } });
  const reports = Array.isArray(data) ? data : (data.reports || []);
  reports.forEach((report) => { if (report.evidence) withEvidenceUrl(report.evidence); });
  return reports;
}

export async function fileReport(findingId) {
  return postJson("/api/reports", { finding_id: findingId });
}

export async function advanceReport(id, to) {
  return postJson(`/api/reports/${id}/advance`, { status: to });
}

function inferScanKind(value) {
  const text = String(value || "").trim();
  const digits = text.replace(/[^\d]/g, "");
  if (/^[+\d][\d\s().-]{4,}$/.test(text) && digits.length >= 6) return "number";
  if (/^https?:\/\//i.test(text) || /\.[a-z]{2,}(?:[/?#]|$)/i.test(text)) return "url";
  return "text";
}

export async function scan(input, kind) {
  const data = await postJson("/api/scan", {
    kind: kind || inferScanKind(input),
    input,
    lang: getLang(),
  });
  return scanResult(data);
}

function scanResult(result) {
  const out = { ...result };
  if (out.finding_id && !out.evidence_url) out.evidence_url = evidenceUrl(out.finding_id);
  return out;
}

/** A SweepRun is created by POST. Unconfigured adapters produce an honest empty run. */
export async function getSweep(channel = "web", query, queryId) {
  const body = { channel, lang: getLang() };
  if (queryId) body.query_id = queryId;
  else if (query) body.query = query;
  const run = await postJson("/api/sweep", body, { timeout: 15000 });
  cacheSet(`sweep:${channel}`, run);
  return withSweepUrls(run);
}

function withSweepUrls(run) {
  run?.results?.forEach(withEvidenceUrl);
  return run;
}

export async function getGuardConfig() {
  return getJson("/api/guard/config", {
    cacheName: "guard:config",
    fallback: { hostname: null, configured: false },
  });
}

export async function getGuardStats() {
  return getJson("/api/guard/stats", {
    cacheName: "guard:stats",
    fallback: { blocked_domains: 0, blocked_hits: 0, blocked_today: 0, feed_size: 0, mode: "unavailable" },
  });
}

/** Canonical sweep queries from the live service. No sample findings or phone numbers. */
export async function getExamples() {
  const empty = { check: [], numbers: [], sweep_web: [], sweep_maps: [] };
  return getJson("/api/examples", { cacheName: "examples", fallback: empty });
}

export async function getStatus() {
  return getJson("/api/status", {
    cacheName: "status",
    fallback: { mode: "unavailable", heartbeats: {}, counts: { domains: 0, findings: 0, evidence: 0 }, uptime_s: 0 },
  });
}

/* ---------------- AI: live SSE and live takedown only -------------- */

export async function streamAnalysis(reportId, { onDelta, signal } = {}) {
  return streamSSE(url(`/api/report/${reportId}/analysis`), { onDelta, signal });
}

async function streamSSE(endpoint, { onDelta, signal }) {
  const response = await fetchWithTimeout(endpoint, {
    method: "POST",
    headers: { Accept: "text/event-stream" },
    signal,
  }, 30000);
  if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let final = null;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() || "";
    for (const frame of frames) {
      let event = "message";
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (!data) continue;
      let payload;
      try { payload = JSON.parse(data); } catch { payload = { delta_text: data }; }
      if (event === "delta" || payload.delta_text) onDelta?.(payload.delta_text ?? "");
      if (event === "final" || payload.summary_en) final = payload;
    }
  }
  if (!final) throw new Error("stream ended without final event");
  setAvailable();
  return final;
}

export async function getTakedown(reportId) {
  return postJson(`/api/report/${reportId}/takedown`, {}, { timeout: 25000 });
}

/* ---------------- SSE: live feed + heartbeat ----------------------- */
export function connectStream({ onFinding, onHeartbeat } = {}) {
  let source = null;
  let retry = null;
  let closed = false;
  let unsubscribe = null;

  const scheduleRetry = () => {
    if (closed || retry) return;
    retry = setTimeout(() => { retry = null; open(); }, 15000);
  };

  const open = () => {
    if (closed || state.offline || state.apiDown) { scheduleRetry(); return; }
    try {
      source = new EventSource(url("/api/stream"));
    } catch {
      setUnavailable();
      scheduleRetry();
      return;
    }
    source.addEventListener("open", () => setAvailable());
    source.addEventListener("finding", (event) => {
      try { onFinding?.(withEvidenceUrl(JSON.parse(event.data))); } catch { /* ignore malformed event */ }
    });
    source.addEventListener("heartbeat", (event) => {
      try { onHeartbeat?.(JSON.parse(event.data)); } catch { /* ignore malformed event */ }
    });
    source.addEventListener("error", () => {
      setUnavailable();
      source?.close();
      source = null;
      scheduleRetry();
    });
  };

  unsubscribe = onState((current) => {
    if (!current.offline && !current.apiDown && !source) open();
  });
  open();

  return {
    available: true,
    close() {
      closed = true;
      if (retry) clearTimeout(retry);
      if (unsubscribe) unsubscribe();
      source?.close();
      source = null;
    },
    inject() {},
  };
}

/* ---------------- evidence helpers -------------------------------- */
export function evidenceUrl(finding) {
  const value = typeof finding === "object" ? finding?.evidence_url : null;
  if (!value) return null;
  const text = String(value);
  if (/^https?:/.test(text)) return text;
  const base = apiBase();
  return base ? `${base}${text.startsWith("/") ? text : `/${text}`}` : text;
}

export function withEvidenceUrl(finding) {
  if (finding && typeof finding === "object") finding.evidence_url = evidenceUrl(finding);
  return finding;
}

/* verdict → tag */
export const VERDICT_TAG = {
  MALICIOUS: "fake", SUSPICIOUS: "warning", MISLEADING: "misleading",
  SAFE: "safe", UNKNOWN: "unknown", QUEUED: "warning",
};
export const tagFor = (verdict) => VERDICT_TAG[String(verdict || "").toUpperCase()] || "unknown";
