/* Daggers · service worker — cache-first app shell + fonts + icons;
   network-first for PUBLIC /api reads only. Checks (POST /api/check) and every
   portal / investigative response always go to the network and are never stored. */
const VERSION = "daggers-v5.0.0";
// Only PUBLIC, non-investigative API reads may be cached on the device.
const PUBLIC_API = new Set(["/api/feed", "/api/status", "/api/guard/stats", "/api/examples", "/api/mode"]);
const SHELL = [
  "./", "./index.html", "./config.js", "./manifest.json",
  "./css/tokens.css", "./css/base.css", "./css/layout.css", "./css/components.css",
  "./js/main.js", "./js/app.js", "./js/api.js",
  "./js/i18n/i18n.js", "./js/i18n/en.json", "./js/i18n/ar.json",
  "./js/components/icons.js", "./js/components/tag.js", "./js/components/toast.js",
  "./js/components/empty.js", "./js/components/skeleton.js", "./js/components/evidence.js",
  "./js/views/_shared.js", "./js/views/feed.js", "./js/views/finding.js", "./js/views/sweep.js",
  "./js/views/check.js", "./js/views/portal.js", "./js/components/analysis.js",
  "./js/views/guard.js", "./js/views/verdict.js", "./js/views/login.js",
  "./fonts/plex-sans-400.woff2", "./fonts/plex-sans-500.woff2", "./fonts/plex-sans-600.woff2",
  "./fonts/plex-sans-700.woff2", "./fonts/plex-mono-400.woff2", "./fonts/plex-mono-500.woff2",
  "./fonts/plex-mono-600.woff2",
  "./fonts/plex-arabic-400.woff2", "./fonts/plex-arabic-500.woff2",
  "./fonts/plex-arabic-600.woff2", "./fonts/plex-arabic-700.woff2",
  "./icons/icon-192.png", "./icons/icon-512.png", "./icons/maskable-512.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    await Promise.allSettled(SHELL.map((u) => cache.add(u)));
    self.skipWaiting();
  })());
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)));
    self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);

  // never buffer a live SSE stream
  if (url.pathname === "/api/stream") return;

  // Investigative / authenticated API data is never stored by the service worker.
  if (url.pathname.startsWith("/api/") && !PUBLIC_API.has(url.pathname)) return;

  // Public API: network-first, last-good cache fallback
  if (url.pathname.startsWith("/api/")) {
    e.respondWith((async () => {
      try {
        const res = await fetch(req);
        const cache = await caches.open(VERSION);
        if (res.ok) cache.put(req, res.clone());
        return res;
      } catch {
        const hit = await caches.match(req, { ignoreVary: true });
        return hit || Response.error();
      }
    })());
    return;
  }

  // shell/assets: cache-first
  e.respondWith((async () => {
    // ignoreVary: static files carry "Vary: Origin" (CORS); module scripts send an Origin
    // header that the precache requests did not, which would otherwise miss the cache offline.
    const hit = await caches.match(req, { ignoreVary: true, ignoreSearch: url.pathname === "/" || url.pathname.endsWith("index.html") });
    if (hit) return hit;
    try {
      const res = await fetch(req);
      if (res.ok && url.origin === self.location.origin) {
        const cache = await caches.open(VERSION);
        cache.put(req, res.clone());
      }
      return res;
    } catch {
      return (await caches.match("./index.html")) || Response.error();
    }
  })());
});
