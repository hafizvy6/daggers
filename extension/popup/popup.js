/* Popup: settings + backend health. No API keys live in the extension. */
(function () {
  "use strict";
  const Core = self.DaggersCore;
  const $ = (id) => document.getElementById(id);
  const status = (text) => { $("status").textContent = text; };

  async function load() {
    const s = await chrome.storage.sync.get({ apiBase: Core.DEFAULT_API_BASE, enabled: true });
    $("apiBase").value = s.apiBase;
    $("enabled").checked = s.enabled !== false;
    health();
  }

  function health() {
    status("Checking backend…");
    chrome.runtime.sendMessage({ type: "health" }, (r) => {
      if (chrome.runtime.lastError || !r) return status("Extension worker unavailable.");
      status(r.ok ? "Backend reachable at " + r.apiBase : "Backend unreachable at " + r.apiBase + " — results will show NOT CHECKED.");
    });
  }

  $("save").addEventListener("click", async () => {
    const origin = Core.validateApiBase($("apiBase").value);
    if (!origin) return status("Use https://… (http is allowed only for localhost / 127.0.0.1).");
    const loopback = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    if (!loopback) {
      const granted = await chrome.permissions.request({ origins: [origin + "/*"] });
      if (!granted) return status("Permission for " + origin + " was not granted.");
    }
    await chrome.storage.sync.set({ apiBase: origin, enabled: $("enabled").checked });
    await new Promise((res) => chrome.runtime.sendMessage({ type: "clearCache" }, res));
    status("Saved.");
    health();
  });

  $("enabled").addEventListener("change", () => chrome.storage.sync.set({ enabled: $("enabled").checked }));
  $("clear").addEventListener("click", () => chrome.runtime.sendMessage({ type: "clearCache" }, () => status("Cache cleared.")));
  load();
})();
