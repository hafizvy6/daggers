// Daggers · independent reputation SAFE path (widely used, non-government sites), in real Chrome.
//
//   BASE=http://127.0.0.1:8000 PORTAL_USER=… PORTAL_PASS=… REPUTATION_FILE=/tmp/x/top-sites.csv \
//     node ops/e2e_reputation.mjs
//
// The server must run with REPUTATION_LIST_PATH=$REPUTATION_FILE and REPUTATION_AUTO_UPDATE=0, and the
// file must NOT exist yet. Mid-run this script writes a small, clearly labelled TEST ranking (list id
// "E2ETEST", ranks illustrative — not the real Tranco list) and checks that the running app picks it up
// without a restart and that the Checker and the Police Portal show the same stored verdict.
// It deletes the test list at the end. Never point it at a real downloaded list.
import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = (() => {
  for (const p of [process.env.PLAYWRIGHT_MODULE, "playwright", "/opt/npm-tools/node_modules/playwright"].filter(Boolean)) {
    try { return require(p); } catch { /* next */ }
  }
  console.error("Playwright not found"); process.exit(2);
})();
const BASE = process.env.BASE || "http://127.0.0.1:8000";
const LIST = process.env.REPUTATION_FILE;
const { PORTAL_USER: USER, PORTAL_PASS: PASS } = process.env;
if (!LIST || !USER || !PASS) { console.error("set REPUTATION_FILE, PORTAL_USER, PORTAL_PASS"); process.exit(2); }
if (fs.existsSync(LIST)) { console.error(`refusing: ${LIST} already exists (this test must not overwrite a real list)`); process.exit(2); }
const META = LIST.replace(/\.csv$/, ".json");
const EXEC = process.env.CHROME || ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));

const results = [];
const check = (name, ok, extra = "") => { results.push(!!ok); console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " — " + extra : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

try {
  // ---- 1. no list yet: a clean, popular site is honestly NOT SAFE
  const before = await runCheck("https://www.youtube.com/");
  check("R1 no reputation list: youtube.com is WARNING (says the list is missing)",
    before.tag === "warning" && /not downloaded yet/i.test(before.text), before.tag);

  // ---- 2. a (TEST) list is installed while the app keeps running
  const ranks = { "google.com": 1, "youtube.com": 2, "whatsapp.com": 20, "github.com": 30, "github.io": 50,
                  "blogspot.com": 60, "bit.ly": 80, "u.ae": 900, "moi.gov.ae": 980 };
  fs.mkdirSync(path.dirname(LIST), { recursive: true });
  fs.writeFileSync(META, JSON.stringify({ list_id: "E2ETEST", retrieved_at: new Date().toISOString(), note: "TEST DATA" }));
  fs.writeFileSync(LIST, Object.entries(ranks).map(([d, r]) => `${r},${d}`).join("\n") + "\n");
  await sleep(2500);                                   // watcher checks at most every 2 s

  const after = await runCheck("https://www.youtube.com/");
  // The Checker never reads the Portal: its stored result was made under the old (empty) list, so it is
  // NOT reused — the link is analysed again and the new result is sent; the Portal corrects its own record.
  check("R2 after the list is installed (no restart): re-checked as SAFE (new analysis, not the old record)",
    after.tag === "safe" && after.id !== before.id, `#${after.id} ${after.tag}`);
  const repeat = await runCheck("https://www.youtube.com/");
  check("R2b same link again: the Checker's stored result is shown directly (same record, no new analysis)",
    repeat.id === after.id && repeat.tag === "safe" && /Stored result/.test(repeat.text), `#${repeat.id}`);
  check("R3 wording: widely used, NOT government; shows the worldwide rank",
    after.text.includes("Widely used website") && after.text.includes("not a government source") &&
    after.text.includes("Worldwide rank") && after.text.includes("E2ETEST") && !after.text.includes("official government domain"));

  const cases = [
    ["https://web.whatsapp.com/", "safe"], ["https://github.com/", "safe"], ["https://www.google.com/", "safe"],
    ["https://evil-shop.github.io/login", "warning"], ["https://docs.google.com/forms/d/e/abc/viewform", "warning"],
    ["https://bit.ly/3abc", "warning"], ["https://www.u.ae/", "warning"], ["https://moi.gov.ae/", "warning"],
    ["https://youtube-login-verify.com/", "not-safe"], ["https://yоutube.com/", "not-safe"],
    ["https://www.youtube.com@evil.top/login", "not-safe"],
  ];
  const seen = [after];
  for (const [url, want] of cases) {
    const r = await runCheck(url);
    seen.push(r);
    check(`R4 ${url} → ${want.toUpperCase()}`, want === "not-safe" ? r.tag !== "safe" : r.tag === want, r.tag);
  }
  const otp = await runCheck("Your WhatsApp account will be closed today. Send us the 6-digit OTP code you received to keep it: https://web.whatsapp.com/");
  seen.push(otp);
  check("R5 OTP scam message linking to WhatsApp is NOT SAFE", otp.tag !== "safe", otp.tag);

  // ---- 3. Police Portal shows the same stored records
  await page.goto(`${BASE}/#/login`);
  await page.fill("#loginUser", USER); await page.fill("#loginPass", PASS);
  await page.click("form button[type=submit]");
  await page.waitForSelector("#portalFindings", { timeout: 20000 }).catch(() => {});
  await page.goto(`${BASE}/#/portal`);
  await page.waitForSelector(`#portalFindings tr[data-finding="${before.id}"]`, { timeout: 20000 }).catch(() => {});
  let same = true;
  for (const r of seen) {
    const rowTag = await page.getAttribute(`#portalFindings tr[data-finding="${r.id}"] [data-tag]`, "data-tag").catch(() => null);
    if (rowTag !== r.tag) { same = false; console.log("   mismatch", r.id, rowTag, r.tag); }
  }
  check("R6 every portal row shows exactly the Checker verdict", same);
  await page.goto(`${BASE}/#/finding/${before.id}`);
  await page.waitForSelector(".analysis", { timeout: 15000 });
  const fp = await page.textContent(".analysis");
  check("R7 portal finding page: SAFE, rank evidence, history of the earlier WARNING",
    (await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag")) === "safe" &&
    fp.includes("Worldwide rank") && fp.includes("Verdict history"));

  // ---- 4. list removed → fail closed, stored record follows
  fs.unlinkSync(LIST);
  await sleep(2500);
  await page.reload();
  await page.waitForSelector(".analysis", { timeout: 15000 });
  check("R8 list removed: the same finding falls back to WARNING",
    (await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag")) === "warning");
  check("R9 no uncaught page errors", errors.length === 0, errors.slice(0, 2).join(" | "));
} finally {
  for (const f of [LIST, META]) { try { fs.unlinkSync(f); } catch { /* gone */ } }
  await browser.close();
}

const failed = results.filter((x) => !x).length;
console.log(failed ? `✗ ${failed} of ${results.length} checks failed` : `✓ all ${results.length} reputation checks passed`);
process.exit(failed ? 1 : 0);
