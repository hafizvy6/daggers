// Daggers · the Checker restores your checks after the browser AND the program are closed and reopened.
//   phase 1:  PHASE=1 BASE=… PROFILE=/tmp/profile node ops/e2e_restore.mjs   (checks two inputs, closes the browser)
//   (stop and start the server)
//   phase 2:  PHASE=2 BASE=… PROFILE=/tmp/profile node ops/e2e_restore.mjs   (reopens: results must be back)
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
const PROFILE = process.env.PROFILE || "/tmp/daggers-restore-profile";
const PHASE = process.env.PHASE || "1";
const EXEC = process.env.CHROME || ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
const results = [];
const check = (name, ok, extra = "") => { results.push(!!ok); console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " — " + extra : ""}`); };

const ctx = await chromium.launchPersistentContext(PROFILE, { executablePath: EXEC, headless: true });
const page = ctx.pages()[0] || await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
await page.goto(`${BASE}/#/check`);
await page.waitForSelector("#checkInput");

if (PHASE === "1") {
  for (const value of ["https://adcb-secure-login.xyz/login", "https://some-unknown-shop.example/"]) {
    await page.fill("#checkInput", value);
    await page.click("#checkBtn");
    await page.waitForSelector("#checkResult .analysis", { timeout: 30000 });
    await page.waitForTimeout(300);
  }
  const rows = await page.$$("#checkHistory [data-history]");
  check("R1 both checks are listed under 'Your recent checks'", rows.length === 2, `${rows.length} rows`);
} else {
  await page.waitForSelector("#checkResult .analysis", { timeout: 15000 }).catch(() => {});
  const restored = await page.$("#restoredNote");
  const tag = await page.getAttribute("#checkResult .verdict-hero [data-tag]", "data-tag").catch(() => null);
  check("R2 after closing and reopening, the last result is shown again (marked as restored)", !!restored && tag === "warning", tag);
  const rows = await page.$$("#checkHistory [data-history]");
  check("R3 the recent-checks list is back", rows.length === 2, `${rows.length} rows`);
  await rows[1].click();
  await page.waitForTimeout(300);
  const older = await page.getAttribute("#checkResult .verdict-hero [data-tag]", "data-tag");
  check("R4 an older check opens with its full result", older === "fake", older);
  await page.click("#clearHistory");
  await page.waitForTimeout(200);
  check("R5 'Clear history' removes it", (await page.$$("#checkHistory [data-history]")).length === 0);
  await page.reload();
  await page.waitForSelector("#checkInput");
  check("R6 after clearing, nothing is restored", !(await page.$("#restoredNote")));
}
check(`R${PHASE === "1" ? "1b" : "7"} no page errors`, errors.length === 0, errors.slice(0, 2).join(" | "));
await ctx.close();
const failed = results.filter((x) => !x).length;
console.log(failed ? `✗ ${failed} of ${results.length} checks failed` : `✓ all ${results.length} restore checks passed (phase ${PHASE})`);
process.exit(failed ? 1 : 0);
