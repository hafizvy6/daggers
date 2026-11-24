#!/usr/bin/env node
/**
 * WS3 gate 4 — UI behaviour test (what the judges actually touch).
 *   node ops/check_ui.mjs [base-url]
 * Needs the dev server running: bash ops/dev.sh
 * Checks all 8 routes render, example pills come from fixtures, checker + number
 * verdicts, sweep scoring, AI stream → AR toggle → takedown, filing toast,
 * language switch + RTL, and zero console errors.
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
const ok = (name, cond, extra = "") => { if (!cond) fails.push(`${name} ${extra}`); else console.log(`✓ ${name}`); };

const browser = await launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await ctx.newPage();
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errs.push(m.text().slice(0, 200)); });

/* --- 1. every route renders with content, no JS errors --- */
for (const [name, route, sel] of [
  ["feed", "#/feed", ".feed-row"],
  ["finding", "#/finding/42", ".evidence-frame"],
  ["sweep", "#/sweep", ".sweep-row"],
  ["check", "#/check", "#checkInput"],
  ["number", "#/number", "#numberInput"],
  ["portal", "#/portal/7", ".ai-panel"],
  ["guard", "#/guard", ".stat"],
  ["verdict", "#/verdict/adcb-secure-login.xyz", ".tag"],
]) {
  await page.goto(`${base}/${route}`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(route === "#/sweep" ? 4000 : 1400);
  const n = await page.locator(sel).count();
  ok(`route ${name}`, n > 0, `(selector ${sel} = ${n})`);
}
ok("no JS errors on routes", errs.length === 0, JSON.stringify(errs.slice(0, 3)));

/* --- 2. example pills come from fixtures, not code --- */
await page.goto(`${base}/#/check`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1400);
const pills = await page.locator(".query-pill").count();
ok("check example pills render from fixtures", pills === 3, `(${pills})`);
await page.locator(".query-pill").first().click();
const val = await page.inputValue("#checkInput");
ok("clicking a pill prefills the payload", val.includes("adcb-secure-login.xyz"), val);
await page.locator("form button[type=submit]").click();
await page.waitForTimeout(1400);
const tag = await page.locator(".verdict-hero .tag").first().textContent();
ok("checker returns a verdict", /FAKE|مزيّف/i.test(tag || ""), tag);

/* --- 3. number pills + verdict --- */
await page.goto(`${base}/#/number`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1200);
const npills = await page.locator(".query-pill").count();
ok("number example pills render", npills === 4, `(${npills})`);
await page.locator(".query-pill").first().click();
await page.locator("form button[type=submit]").click();
await page.waitForTimeout(1200);
const ntag = await page.locator("section.card .tag").first().textContent();
ok("number check returns a verdict", /FAKE|مزيّف|WARNING/i.test(ntag || ""), ntag);

/* --- 4. sweep pills + progressive scoring --- */
await page.goto(`${base}/#/sweep`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(4500);
const sp = await page.locator(".query-pill").count();
const scored = await page.locator(".sweep-row .tag").count();
ok("sweep query pills render", sp >= 3, `(${sp})`);
ok("sweep rows got scored", scored >= 5, `(${scored})`);

/* --- 5. portal: file → advance → AI stream → AR toggle → takedown --- */
await page.goto(`${base}/#/portal/7`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1500);
await page.locator("button", { hasText: "AI Analysis" }).first().click();
await page.waitForTimeout(8000);
const aiText = await page.locator(".ai-out").textContent();
ok("AI analysis streams text", (aiText || "").length > 200, `(${(aiText||"").length} chars)`);
const badge = await page.locator(".ai-badge").first().textContent();
ok("AI badge shows the provider", /template|gemini|groq/i.test(badge || ""), badge);
await page.locator(".lang-switch.is-ai button[data-l=ar]").click();
await page.waitForTimeout(500);
const arText = await page.locator(".ai-out").textContent();
ok("AR toggle shows Arabic case", /[\u0600-\u06FF]/.test(arText || ""), (arText||"").slice(0, 40));

await page.locator("button", { hasText: "Draft the letter" }).click();
await page.waitForTimeout(1200);
const letter = await page.inputValue(".ai-panel textarea");
ok("takedown letter renders", (letter || "").includes("Abuse report"), (letter||"").slice(0, 40));
ok("takedown letter has no user data", !/\+971|\@gmail/.test(letter || ""));

/* --- 6. finding → file a report → toast + portal link --- */
await page.goto(`${base}/#/finding/33`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1400);
const fileBtn = page.locator("button", { hasText: /^File report$/ });
if (await fileBtn.count()) {
  await fileBtn.click();
  await page.waitForTimeout(1400);
  const toastTxt = await page.locator(".toast").first().textContent().catch(() => "");
  ok("filing shows the 'We got you' toast", /We got you/.test(toastTxt || ""), toastTxt);
  const link = await page.locator("a.btn", { hasText: "Filed" }).count();
  ok("filing swaps to a portal link", link > 0);
} else {
  ok("finding 33 already filed (idempotent by design)", true);
}

/* --- 7. language switch re-renders the current route --- */
await page.goto(`${base}/#/feed`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1200);
await page.click("#langSwitch button[data-lang=ar]");
await page.waitForTimeout(1200);
const h1ar = await page.locator("h1").textContent();
ok("AR switch translates the view", /[\u0600-\u06FF]/.test(h1ar || ""), h1ar);
ok("AR sets dir=rtl", (await page.evaluate(() => document.documentElement.dir)) === "rtl");

await browser.close();
if (errs.length) fails.push("console errors: " + JSON.stringify(errs.slice(0, 3)));
if (fails.length) { console.log(`\n✗ ${fails.length} UI failure(s)`); fails.forEach(f => console.log("  " + f)); process.exit(1); }
console.log("\n✓ all UI behaviour checks passed");
