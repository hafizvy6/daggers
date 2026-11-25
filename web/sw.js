/* Daggers · service worker — cache-first shell; network-first for live API GETs.
   Only real successful API responses are cached. No fixture or evidence bundle. */
const VERSION = "daggers-live-v4.0.1";
const SHELL = [
  "./", "./index.html", "./config.js", "./manifest.json",
  "./css/tokens.css", "./css/base.css", "./css/layout.css", "./css/components.css",
  "./js/app.js", "./js/api.js",
  "./js/i18n/i18n.js", "./js/i18n/en.json", "./js/i18n/ar.json",
  "./js/components/icons.js", "./js/components/tag.js", "./js/components/toast.js",
  "./js/components/empty.js", "./js/components/skeleton.js", "./js/components/evidence.js",
  "./js/views/_shared.js", "./js/views/feed.js", "./js/views/finding.js", "./js/views/sweep.js",
  "./js/views/check.js", "./js/views/number.js", "./js/views/portal.js",
  "./js/views/portal_fallback.js", "./js/views/guard.js", "./js/views/verdict.js",
  "./fonts/plex-sans-400.woff2", "./fonts/plex-sans-500.woff2", "./fonts/plex-sans-600.woff2",
  "./fonts/plex-sans-700.woff2", "./fonts/plex-mono-400.woff2", "./fonts/plex-mono-500.woff2",
  "./fonts/plex-mono-600.woff2",
  "./fonts/plex-arabic-400.woff2", "./fonts/plex-arabic-500.woff2",
  "./fonts/plex-arabic-600.woff2", "./fonts/plex-arabic-700.woff2",
  "./icons/logo.png", "./icons/icon-192.png", "./icons/icon-512.png", "./icons/maskable-512.png", "./icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    await Promise.allSettled(SHELL.map((path) => cache.add(path)));
    self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key !== VERSION).map((key) => caches.delete(key)));
    self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);

  // Never buffer a live SSE stream.
  if (url.pathname === "/api/stream") return;

  // API GET: network-first, with a last-good REAL response only.
  if (url.pathname.startsWith("/api/")) {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (response.ok) {
          const cache = await caches.open(VERSION);
          cache.put(request, response.clone());
        }
        return response;
      } catch {
        const cached = await caches.match(request);
        return cached || Response.error();
      }
    })());
    return;
  }

  // Static shell/assets: cache-first, with an app-shell fallback for navigation.
  event.respondWith((async () => {
    const cached = await caches.match(request, {
      ignoreSearch: url.pathname === "/" || url.pathname.endsWith("index.html"),
    });
    if (cached) return cached;
    try {
      const response = await fetch(request);
      if (response.ok && url.origin === self.location.origin) {
        const cache = await caches.open(VERSION);
        cache.put(request, response.clone());
      }
      return response;
    } catch {
      return (await caches.match("./index.html")) || Response.error();
    }
  })());
});
