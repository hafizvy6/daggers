// Daggers · government authentication → verdict → database → Checker / Police Portal, in real Chrome.
//
//   BASE=http://127.0.0.1:8000 PORTAL_USER=… PORTAL_PASS=… REGISTRY_FILE=/path/to/COPY/registry.yaml \
//     node ops/e2e_government.mjs
//
// The server must have been started with OFFICIAL_REGISTRY_PATH=$REGISTRY_FILE (a COPY of the registry).
// Mid-run this script applies TEST approvals (reviewer "E2E Test Reviewer") to that copy — never to the
// shipped registry — and verifies the running app picks them up without a restart.
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import path from "node:path";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = (() => {
  for (const p of [process.env.PLAYWRIGHT_MODULE, "playwright", "/opt/npm-tools/node_modules/playwright"].filter(Boolean)) {
    try { return require(p); } catch { /* next */ }
  }
  console.error("Playwright not found"); process.exit(2);
})();
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const SHIPPED = path.join(ROOT, "backend/app/channels/official/registry.yaml");
const BASE = process.env.BASE || "http://127.0.0.1:8000";
const REG = process.env.REGISTRY_FILE;
const { PORTAL_USER: USER, PORTAL_PASS: PASS } = process.env;
if (!REG || !USER || !PASS) { console.error("set REGISTRY_FILE, PORTAL_USER, PORTAL_PASS"); process.exit(2); }
if (path.resolve(REG) === path.resolve(SHIPPED)) { console.error("refusing: REGISTRY_FILE must be a COPY"); process.exit(2); }
const EXEC = process.env.CHROME || ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
const VERIFIED = "uae-gov-portal uae-pass abu-dhabi-police dubai-police icp mohre rta dewa tamm wam abu-dhabi-media-office dubai-media-office khaleej-times gulf-news emirates-nbd".split(" ");

const results = [];
const check = (name, ok, extra = "") => { results.push(!!ok); console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " — " + extra : ""}`); };
const registryCli = (...args) => execFileSync("python3", ["-m", "backend.app.channels.official.cli", "--registry", REG, ...args],
  { cwd: ROOT, env: { ...process.env, PYTHONPATH: ROOT }, stdio: "pipe" }).toString();

const browser = await chromium.launch({ executablePath: EXEC, headless: true });
const page = await (await browser.newContext()).newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));

async function runCheck(value) {
  await page.goto(`${BASE}/#/check`);
  await page.waitForSelector("#checkInput");
  await page.fill("#checkInput", value);
  await page.click("#checkBtn");
  await page.waitForSelector("#checkResult .analysis", { timeout: 30000 });
  const note = (await page.textContent("#checkResult .note")) || "";
  return {
    id: Number((note.match(/#(\d+)/) || [])[1]),
    tag: await page.getAttribute("#checkResult .verdict-hero [data-tag]", "data-tag"),
    text: await page.textContent("#checkResult .analysis"),
  };
}

// ---- 1. registry still pending: the genuine site is NOT SAFE (honest state)
const before = await runCheck("https://www.adpolice.gov.ae/en");
check("G1 pending registry: www.adpolice.gov.ae is WARNING", before.tag === "warning" && /pending/i.test(before.text), before.tag);

// ---- 2. a reviewer approves the verified entries (TEST approval on the copy); app keeps running
for (const id of VERIFIED) registryCli("approve", id, "--reviewer", "E2E Test Reviewer", "--yes");
await new Promise((r) => setTimeout(r, 2500));      // registry watcher checks at most every 2 s

const after = await runCheck("https://www.adpolice.gov.ae/en");
// The Checker never reads the Portal: the stored result from before the approval is not reused; the
// link is analysed again (SAFE) and sent as a new record. The Portal corrects its own old record (G9).
check("G2 after approval (no restart): re-checked as SAFE (new analysis)", after.id !== before.id && after.tag === "safe", `#${after.id} ${after.tag}`);
check("G3 Checker shows government wording + approval details",
  after.text.includes("official government domain") && after.text.includes("E2E Test Reviewer") && after.text.includes("Approval expires"));
check("G4 the repeated check is a fresh analysis (no stored result reused across the registry change)",
  !/Stored result/.test(after.text));

const cases = [
  ["https://u.ae/en", "safe"], ["https://smartservices.icp.gov.ae/", "safe"], ["https://www.tamm.abudhabi/", "safe"],
  ["https://www.emiratesnbd.com/en", "safe"], ["https://www.khaleejtimes.com/", "safe"],
  ["https://www.thenationalnews.com/", "warning"], ["https://www.u.ae/", "warning"], ["https://evil.adpolice.gov.ae/", "warning"],
  ["https://adpolice-gov.ae/", "fake"], ["https://www.adpolice.gov.ae@evil.top/login", "fake"], ["https://аdpolice.gov.ae/", "fake"],
];
const ids = {};
for (const [url, want] of cases) {
  const r = await runCheck(url);
  ids[url] = r;
  check(`G5 ${url} → ${want.toUpperCase()}`, r.tag === want, r.tag);
}
check("G6 SAFE company/news is never called official",
  ids["https://www.emiratesnbd.com/en"].text.includes("not a government source") &&
  !ids["https://www.emiratesnbd.com/en"].text.includes("official government domain"));
const otp = await runCheck("Abu Dhabi Police: your fine is unpaid. Send us the OTP you received to clear it: https://www.adpolice.gov.ae");
check("G7 OTP request linking to the genuine police site is NOT SAFE", otp.tag !== "safe", otp.tag);

// ---- 3. Police Portal shows the same records
await page.goto(`${BASE}/#/login`);
await page.fill("#loginUser", USER); await page.fill("#loginPass", PASS);
await page.click("form button[type=submit]");
await page.waitForSelector("#portalFindings", { timeout: 20000 }).catch(() => {});
await page.goto(`${BASE}/#/portal`);
await page.waitForSelector(`#portalFindings tr[data-finding="${before.id}"]`, { timeout: 20000 }).catch(() => {});
let same = true;
for (const r of [after, ...Object.values(ids), otp]) {
  const rowTag = await page.getAttribute(`#portalFindings tr[data-finding="${r.id}"] [data-tag]`, "data-tag").catch(() => null);
  if (rowTag !== r.tag) { same = false; console.log("   mismatch", r.id, rowTag, r.tag); }
}
check("G8 every portal row shows exactly the Checker verdict", same);
await page.goto(`${BASE}/#/finding/${before.id}`);
await page.waitForSelector(".analysis", { timeout: 15000 });
const fp = await page.textContent(".analysis");
check("G9 portal finding page: SAFE, approved by, expiry, history",
  (await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag")) === "safe" &&
  fp.includes("E2E Test Reviewer") && fp.includes("Verdict history"));
await page.reload();
await page.waitForSelector(".analysis", { timeout: 15000 });
check("G10 after reload the stored verdict is unchanged",
  (await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag")) === "safe");

// ---- 4. revocation flows back to the same stored record
registryCli("revoke", "abu-dhabi-police", "--reviewer", "E2E Test Reviewer", "--reason", "e2e revocation test");
await new Promise((r) => setTimeout(r, 2500));
await page.reload();
await page.waitForSelector(".analysis", { timeout: 15000 });
const revoked = await page.textContent(".analysis");
check("G11 revocation: same finding becomes WARNING (revoked) in the portal",
  (await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag")) === "warning" && /revoked/i.test(revoked));
check("G12 no uncaught page errors", errors.length === 0, errors.slice(0, 2).join(" | "));
await browser.close();

const failed = results.filter((x) => !x).length;
console.log(failed ? `✗ ${failed} of ${results.length} checks failed` : `✓ all ${results.length} government checks passed`);
process.exit(failed ? 1 : 0);
