/*
 * Daggers Shield — pure helpers shared by the content script, the service worker,
 * the popup and the Node tests. No DOM, no chrome.* calls, no network here.
 *
 * The extension NEVER computes a verdict. It only displays the backend's `tag`.
 * SAFE is shown only when the backend says tag === "SAFE" AND reports either an
 * authenticated official (government) domain or an approved legitimate site
 * (news outlet / verified organisation). Any failure, missing field or unknown value
 * is displayed as a neutral "not checked" / "unverified" label — never green.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.DaggersCore = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const DEFAULT_API_BASE = "http://localhost:8000";
  const REQUEST_TIMEOUT_MS = 6000;
  const CACHE_TTL_MS = 30 * 60 * 1000;
  const NEGATIVE_TTL_MS = 60 * 1000;
  const MAX_URL_LENGTH = 2048;

  // Containers that hold ads, map/local packs, or non-organic modules.
  const EXCLUDED_ANCESTORS = [
    "#tads", "#tadsb", "#bottomads", "[data-text-ad]", "[data-pla]", ".commercial-unit-desktop-top",
    "[aria-label='Ads']", "[aria-label='Sponsored']", "[aria-label='Sponsored results']",
    "[data-local-attribute]", "g-map", "[data-attrid*='kc:/location']", ".VkpGBb", "#lu_map",
    "g-scrolling-carousel", "[data-daggers-tag]"
  ];

  const LABELS = {
    SAFE: { text: "SAFE", cls: "daggers-tag--safe", title: "Authenticated official government source with no suspicious signals." },
    SAFE_SITE: { text: "SAFE", cls: "daggers-tag--safe", title: "Verified legitimate website (not a government source) with no suspicious signals." },
    SAFE_ESTABLISHED: { text: "SAFE", cls: "daggers-tag--safe", title: "Established website (old domain, HTTPS, no warning signs) — not a government source." },
    SAFE_POPULAR: { text: "SAFE", cls: "daggers-tag--safe", title: "Widely used website (not a government source) with no warning signs." },
    WARNING: { text: "WARNING", cls: "daggers-tag--warning", title: "Not an authenticated official source, or needs review." },
    MISLEADING: { text: "MISLEADING", cls: "daggers-tag--misleading", title: "Contains a claim that is contradicted or cannot be verified." },
    FAKE: { text: "FAKE", cls: "daggers-tag--fake", title: "Confirmed malicious or impersonation evidence." },
    UNVERIFIED: { text: "UNVERIFIED", cls: "daggers-tag--warning", title: "Backend did not authenticate this domain. Not the same as safe." },
    UNCHECKED: { text: "NOT CHECKED", cls: "daggers-tag--unchecked", title: "Daggers could not check this result (backend unavailable)." }
  };

  // Used only when the backend predates the trust-policy fields (no `tag`).
  // UNKNOWN maps to UNVERIFIED, never SAFE.
  const LEGACY_VERDICT_LABEL = { MALICIOUS: "FAKE", MISLEADING: "MISLEADING", SUSPICIOUS: "WARNING", UNKNOWN: "UNVERIFIED" };

  function sanitizeResultUrl(raw) {
    if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) return null;
    let url;
    try { url = new URL(raw); } catch (_) { return null; }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    if (!url.hostname || url.hostname.indexOf(".") === -1) return null;
    // Privacy: never send query strings or fragments (may carry tokens or personal data).
    return url.protocol + "//" + url.host + url.pathname;
  }

  function isGoogleHost(hostname) {
    const h = String(hostname || "").toLowerCase();
    return /(^|\.)google\.[a-z.]+$/.test(h) || /(^|\.)(googleusercontent|gstatic|googleadservices|youtube)\.com$/.test(h);
  }

  /** el: anything with closest(selector) and an href. Returns {ok, reason}. */
  function classifyResultLink(el) {
    if (!el || typeof el.closest !== "function") return { ok: false, reason: "no element" };
    for (const selector of EXCLUDED_ANCESTORS) {
      try { if (el.closest(selector)) return { ok: false, reason: "excluded container " + selector }; } catch (_) { /* invalid selector in old engines */ }
    }
    let url;
    try { url = new URL(el.href); } catch (_) { return { ok: false, reason: "bad href" }; }
    if (isGoogleHost(url.hostname)) return { ok: false, reason: "internal google link" };
    if (/^\/(maps|aclk|url|search)/.test(url.pathname) && isGoogleHost(url.hostname)) return { ok: false, reason: "google path" };
    if (!sanitizeResultUrl(el.href)) return { ok: false, reason: "unsupported url" };
    return { ok: true, reason: "organic result" };
  }

  /** Map a backend response (or failure) to a display label. Never fabricates SAFE. */
  function labelFor(response) {
    if (!response || response.error || typeof response !== "object") return LABELS.UNCHECKED;
    const tag = response.tag;
    if (tag === "SAFE") {
      const auth = response.domain_auth;
      if (auth && auth.authenticated === true) return LABELS.SAFE;
      if (auth && auth.legitimate_site === true) {
        if (auth.status === "REPUTABLE_SITE") return LABELS.SAFE_POPULAR;
        if (auth.status === "ESTABLISHED_SITE") return LABELS.SAFE_ESTABLISHED;
        return LABELS.SAFE_SITE;
      }
      return LABELS.UNVERIFIED;
    }
    if (tag === "WARNING" || tag === "MISLEADING" || tag === "FAKE") return LABELS[tag];
    if (tag === undefined || tag === null) {
      const legacy = LEGACY_VERDICT_LABEL[response.verdict];
      return legacy ? LABELS[legacy] : LABELS.UNCHECKED;
    }
    return LABELS.UNCHECKED;
  }

  function tooltipFor(response, label) {
    if (!response || response.error) return label.title;
    const lines = [label.title];
    const reasons = (response.trust_reasons && response.trust_reasons.length ? response.trust_reasons : response.reasons) || [];
    for (const r of reasons.slice(0, 3)) lines.push("• " + String(r).slice(0, 160));
    return lines.join("\n");
  }

  /** Only http on loopback, otherwise https. Returns the origin or null. */
  function validateApiBase(value) {
    let url;
    try { url = new URL(String(value || "").trim()); } catch (_) { return null; }
    const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.username || url.password) return null;
    if (url.protocol === "https:" || (url.protocol === "http:" && loopback)) return url.origin;
    return null;
  }

  function pickFields(body) {
    // Keep only what the UI needs; the cache never stores the request input echo.
    if (!body || typeof body !== "object") return { error: "bad_response" };
    return {
      tag: body.tag === undefined ? undefined : body.tag,
      verdict: body.verdict,
      domain_auth: body.domain_auth ? {
        authenticated: body.domain_auth.authenticated === true,
        legitimate_site: body.domain_auth.legitimate_site === true,
        status: body.domain_auth.status
      } : null,
      trust_reasons: Array.isArray(body.trust_reasons) ? body.trust_reasons.slice(0, 5) : undefined,
      reasons: Array.isArray(body.reasons) ? body.reasons.slice(0, 5) : []
    };
  }

  return {
    DEFAULT_API_BASE, REQUEST_TIMEOUT_MS, CACHE_TTL_MS, NEGATIVE_TTL_MS, EXCLUDED_ANCESTORS, LABELS,
    sanitizeResultUrl, isGoogleHost, classifyResultLink, labelFor, tooltipFor, validateApiBase, pickFields
  };
});
