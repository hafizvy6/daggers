#!/usr/bin/env node
/* Daggers · Guard browser test (real Chrome against a running server).
   BASE=http://127.0.0.1:8000 node ops/e2e_guard.mjs
   Uses only live API calls: a Checker link check of an obvious bank-lookalike login URL must be
   listed by the Guard, appear on the Guard page live (SSE), and open the verdict page. */
import { createRequire } from "node:module";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = (() => {
  for (const p of [process.env.PLAYWRIGHT_MODULE, "playwright", "/opt/npm-tools/node_modules/playwright"].filter(Boolean)) {
    try { return require(p); } catch { /* next */ }
  }
  console.error("Playwright not found"); process.exit(2);
})();
const BASE = process.env.BASE || "http://127.0.0.1:8000";
const SHOTS = process.env.SHOTS || "";
const EXEC = process.env.CHROME || ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
const results = [];
const check = (name, ok, extra = "") => { results.push(!!ok); console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " — " + extra : ""}`); };
const api = async (path, init) => (await fetch(BASE + path, init)).json();
const rid = () => `e2e-guard-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

const browser = await chromium.launch({ executablePath: EXEC, headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
try {
  const stats0 = await api("/api/guard/stats");
  check("stats endpoint answers with live keys", "blocklist_count" in stats0 && "honest_limits_key" in stats0);

  await page.goto(`${BASE}/#/guard`, { waitUntil: "networkidle" });
  const body = await page.textContent("#view");
  check("no made-up DoT hostname on the page", !body.includes("daggers-guard.nextdns.io"));
  if (!stats0.dot_hostname) check("'not configured' shown instead of a hostname", body.includes("not configured"));
  const blocklistInput = await page.$(`input[value="${stats0.blocklist_url}"]`);
  check("blocklist URL is shown and copyable", !!blocklistInput);
  if (stats0.doh_url) check("DoH URL is shown", !!(await page.$(`input[value="${stats0.doh_url}"]`)));
  check("honest limits match the mode", body.includes(stats0.guard_mode === "list_only" ? "nothing is blocked on phones" :
    stats0.guard_mode === "doh" ? "There is no branded page" : stats0.guard_mode === "nextdns" ? "NextDNS" : "certificate"));

  // live loop: a Checker link check while the page is open
  const url = "https://dubaipolice-fines-pay.top/login";
  const res = await api("/api/check", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: url, request_id: rid() }) });
  check("Checker verdict is FAKE", res.tag === "FAKE", res.tag);
  check("Checker response carries the Guard state", res.guard?.blocked === true, JSON.stringify(res.guard));
  await page.waitForFunction((d) => document.querySelector("#view")?.textContent.includes(d),
    "dubaipolice-fines-pay.top", { timeout: 8000 }).then(() => check("new fake appears on the Guard page live (SSE)", true))
    .catch(() => check("new fake appears on the Guard page live (SSE)", false));
  const rowText = await page.textContent("#view");
  check("newest fake shows its source badge", rowText.includes("Checker"));
  check("blocklist count went up", (await api("/api/guard/stats")).blocklist_count >= stats0.blocklist_count + (stats0.newest_fakes.some((r) => r.domain === "dubaipolice-fines-pay.top") ? 0 : 1));
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/guard-en.png`, fullPage: true });

  // test bar
  await page.fill('input[aria-label="Domain to test"]', "dubaipolice-fines-pay.top");
  await page.click('form.input-row button[type="submit"]');
  await page.waitForFunction(() => document.querySelector("#view")?.textContent.includes("Blocked by the Guard"), null, { timeout: 15000 })
    .then(() => check("test bar: Guard + Checker says blocked", true)).catch(() => check("test bar: Guard + Checker says blocked", false));
  await page.fill('input[aria-label="Domain to test"]', "example.org");
  await page.click('form.input-row button[type="submit"]');
  await page.waitForFunction(() => document.querySelector("#view")?.textContent.includes("Not on the Guard list"), null, { timeout: 15000 })
    .then(() => check("test bar: unlisted domain is not blocked", true)).catch(() => check("test bar: unlisted domain is not blocked", false));

  // preview verdict
  await page.click('a[href="#/verdict/dubaipolice-fines-pay.top"]');
  await page.waitForFunction(() => location.hash.startsWith("#/verdict/") && document.querySelector(".vh-domain"), null, { timeout: 8000 });
  check("Preview verdict shows the blocked domain", (await page.textContent(".vh-domain")).includes("dubaipolice-fines-pay.top"));

  // real verdict landing (/verdict?domain=…&hit=1) counts one anonymous block
  const before = (await api("/api/guard/stats")).blocked_total;
  await page.goto(`${BASE}/verdict?domain=dubaipolice-fines-pay.top&hit=1`, { waitUntil: "networkidle" });
  await page.waitForSelector(".vh-domain", { timeout: 8000 });
  check("/verdict landing renders the verdict view", (await page.textContent("#view")).includes("stopped this site"));
  const after = (await api("/api/guard/stats")).blocked_total;
  const doubleCountGuard = stats0.guard_mode === "doh_verdict";
  check("verdict visit counted exactly once", doubleCountGuard ? after === before : after === before + 1, `${before} → ${after}`);

  // Arabic
  await page.evaluate(() => localStorage.setItem("daggers.lang", "ar"));
  await page.goto(`${BASE}/#/guard`, { waitUntil: "networkidle" });
  check("Arabic: page is RTL", (await page.getAttribute("html", "dir")) === "rtl");
  check("Arabic: test bar translated", (await page.textContent("#view")).includes("اختبر نطاقًا"));
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/guard-ar.png`, fullPage: true });
  await page.goto(`${BASE}/#/verdict/dubaipolice-fines-pay.top`, { waitUntil: "networkidle" });
  await page.waitForSelector(".vh-domain", { timeout: 8000 });
  check("Arabic: verdict page translated", (await page.textContent("#view")).includes("أوقف الحارس"));
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/verdict-ar.png`, fullPage: true });
  await page.evaluate(() => localStorage.setItem("daggers.lang", "en"));
} catch (err) {
  check("no unexpected error", false, String(err?.message || err));
} finally {
  await browser.close();
}
const passed = results.filter(Boolean).length;
console.log(`\n${passed}/${results.length} Guard checks passed`);
process.exit(passed === results.length ? 0 : 1);
