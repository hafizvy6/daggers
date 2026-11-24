#!/usr/bin/env node
/**
 * WS3 gate 3 — runtime purity + DEMO_MODE offline story.
 *  1) every request the app makes at runtime is same-origin (no CDNs, no fonts.google)
 *  2) ?mode=demo works with the network hard-off after first load
 *  3) the radar demo beat lands a new finding without any network
 */
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
// Resolve Playwright, in order of preference:
//   1. PLAYWRIGHT_MODULE  — explicit override
//   2. a normal `npm i playwright` in this folder (node_modules/playwright)
//   3. a global install    — `npm i -g playwright` or Homebrew
//   4. ~/tools/playwright  — the lane's own optional copy
//   5. an executable on PATH (last resort)
import { execSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

function globalRoot() {
  try { return execSync("npm root -g", { encoding: "utf8" }).trim(); } catch { return ""; }
}

const CANDIDATES = [
  process.env.PLAYWRIGHT_MODULE,
  "playwright",
  globalRoot() && join(globalRoot(), "playwright"),
  join(homedir(), "tools", "playwright", "node_modules", "playwright"),
].filter(Boolean);

let chromium;
const tried = [];
for (const candidate of CANDIDATES) {
  tried.push(candidate);
  try { ({ chromium } = require(candidate)); break; } catch { /* next */ }
}
if (!chromium) {
  console.error(
    "✗ this gate needs Playwright, and none was found.\n" +
    "  tried:\n    " + tried.join("\n    ") + "\n\n" +
    "  you said it's installed — if `npm ls -g playwright` shows it but this\n" +
    "  still fails, point at it directly:\n" +
    "    PLAYWRIGHT_MODULE=$(npm root -g)/playwright node ops/check_ui.mjs\n\n" +
    "  otherwise install it:  npm i -g playwright && npx playwright install chromium\n\n" +
    "  everything except the 3 browser gates still runs:\n" +
    "    python3 ops/check_i18n.py && python3 -m pytest backend/tests -q"
  );
  process.exit(2);
}

// Launch with a readable message if the module is present but the browser isn't.
async function launch() {
  try {
    return await chromium.launch();
  } catch (err) {
    const msg = String(err && err.message || err);
    if (/Executable doesn't exist|is not found|Failed to launch/i.test(msg)) {
      console.error(
        "✗ Playwright is installed but its browser isn't.\n" +
        "  install it once:  npx playwright install chromium\n" +
        "  (Linux needing system libs:  sudo npx playwright install-deps chromium)"
      );
      process.exit(3);
    }
    throw err;
  }
}

const base = process.argv[2] || "http://127.0.0.1:8080";
const fails = [];
const browser = await launch();

// ---- 1) external request scan ----
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const external = new Set();
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.origin !== new URL(base).origin && !u.protocol.startsWith("data")) external.add(r.url());
  });
  for (const r of ["#/feed", "#/finding/42", "#/sweep", "#/portal/7", "#/guard", "#/check", "#/number"]) {
    await page.goto(`${base}/${r}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1400);
  }
  if (external.size) fails.push(`external requests: ${[...external].slice(0, 5).join(", ")}`);
  await ctx.close();
}

// ---- 2) offline demo: load, then kill the network ----
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${base}/?mode=demo#/feed`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  await ctx.setOffline(true);
  const checks = {};
  for (const [name, route] of [["feed", "#/feed"], ["finding", "#/finding/42"], ["portal", "#/portal/7"], ["check", "#/check"], ["guard", "#/guard"]]) {
    await page.goto(`${base}/${route}`, { waitUntil: "domcontentloaded" }).catch(() => {});
    await page.waitForTimeout(1100);
    checks[name] = await page.evaluate(() => ({
      rows: document.querySelectorAll(".feed-row, .table tbody tr, .evidence-frame, .card").length,
      banner: document.getElementById("banner")?.textContent?.includes("offline") ||
              document.getElementById("banner")?.textContent?.includes("غير متصل") ||
              document.getElementById("banner")?.textContent?.includes("DEMO"),
    }));
    if (!checks[name].rows) fails.push(`offline ${name}: view is empty`);
  }
  // checker still answers offline
  await page.goto(`${base}/?mode=demo#/check`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(900);
  await page.fill("#checkInput", "https://adcb-secure-login.xyz/verify");
  await page.locator("form button[type=submit]").click();
  await page.waitForTimeout(1200);
  const verdict = await page.evaluate(() => document.querySelector(".verdict-hero .tag")?.textContent?.trim());
  if (!verdict) fails.push("offline checker: no verdict card");
  // demo radar beat (fires at ~14s)
  await page.goto(`${base}/?mode=demo#/feed`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(16500);
  const beat = await page.evaluate(() => ({
    first: document.querySelector(".feed-row .fr-domain")?.textContent?.trim(),
    isNew: !!document.querySelector(".feed-row.is-new"),
  }));
  if (!/adcb-login-verify/.test(beat.first || "")) fails.push(`offline demo beat: expected new finding first, got ${beat.first}`);
  await ctx.close();
}

await browser.close();
if (fails.length) {
  console.log(`✗ purity/offline gate: ${fails.length} issue(s)`);
  fails.forEach((f) => console.log("  " + f));
  process.exit(1);
}
console.log("✓ purity/offline gate clean — same-origin only; DEMO_MODE survives network-off incl. radar beat");
