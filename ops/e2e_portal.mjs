// Daggers · LIVE acceptance test in a real browser (Playwright + Chrome).
//
//   BASE=http://127.0.0.1:8000 PORTAL_USER=… PORTAL_PASS=… node ops/e2e_portal.mjs
//   (PORTAL_USER must be an investigator or admin account on that server)
//
// A. The acceptance workflow: Checker → URL → full result → Police Portal shows the SAME
//    finding → open it → evidence → back to Checker → suspicious message → analysis →
//    portal shows the second finding → reload: both still there, no duplicates.
// B. Input validation, backend unavailable, Arabic UI, mobile layout.
// C. Portal investigation → report → AI Analyst.   D. Chrome extension = /api/scan tag.
// Exit code 0 only if every check passes.
import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";

const require = createRequire(import.meta.url);
function loadPlaywright() {
  const tries = [process.env.PLAYWRIGHT_MODULE, "playwright", "/opt/npm-tools/node_modules/playwright"].filter(Boolean);
  for (const p of tries) { try { return require(p); } catch { /* next */ } }
  console.error("Playwright not found (npm i -g playwright). Tried:", tries.join(", "));
  process.exit(2);
}
const { chromium } = loadPlaywright();
const BASE = process.env.BASE || "http://127.0.0.1:8000";
const USER = process.env.PORTAL_USER, PASS = process.env.PORTAL_PASS;
const EXEC = process.env.CHROME || ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
const RUN = Date.now().toString(36);                       // makes this run's inputs unique
const URL_IN = `https://adcb-secure-login-${RUN}.xyz/login?utm_source=sms`;
const MSG_IN = `Emirates Post: your parcel is on hold due to an unpaid customs fee of AED 12.50. `
  + `Pay within 24 hours at https://emiratespost-${RUN}.top/pay or call 050 123 4567`;
const results = [];
const check = (name, ok, extra = "") => { results.push({ name, ok: !!ok }); console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " — " + extra : ""}`); };

if (!USER || !PASS) { console.error("set PORTAL_USER and PORTAL_PASS (an investigator account)"); process.exit(2); }

const browser = await chromium.launch({ executablePath: EXEC, headless: true });
const context = await browser.newContext();
const page = await context.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => { if (m.type() === "error" && !/401|403|429|503|Failed to load resource|ERR_FAILED/.test(m.text())) errors.push(m.text()); });
const api = (p, init) => page.evaluate(async ([p, init]) => {
  const r = await fetch(p, { credentials: "same-origin", ...(init || {}) }); return { status: r.status, body: await r.json().catch(() => null) };
}, [p, init]);

async function runCheck(value) {
  await page.goto(`${BASE}/#/check`);
  await page.waitForSelector("#checkInput");
  await page.fill("#checkInput", value);
  await page.click("#checkBtn");
  await page.waitForSelector("#checkResult .analysis, #checkResult [role=alert]", { timeout: 30000 });
  const savedText = (await page.textContent("#checkResult .note").catch(() => "")) || "";
  const id = Number((savedText.match(/#(\d+)/) || [])[1]);
  const tag = await page.getAttribute("#checkResult .verdict-hero [data-tag]", "data-tag").catch(() => null);
  return { id, tag, savedText };
}

// ---------------------------------------------------------------- A. acceptance workflow
// 1–6: Checker → URL → complete result
const first = await runCheck(URL_IN);
check("A1 URL check completes and is saved as a finding", Number.isFinite(first.id) && first.id > 0, first.savedText.trim().slice(0, 60));
check("A2 result shows a verdict", ["safe", "warning", "misleading", "fake"].includes(first.tag), first.tag);
check("A3 normalised URL shown (tracking parameter removed)",
  await page.isVisible(`#checkResult >> text=https://adcb-secure-login-${RUN}.xyz/login`) &&
  !(await page.textContent("#checkResult .analysis")).includes("utm_source"));
check("A4 detection signals listed", (await page.$$("#checkResult details.signal")).length >= 2);
await page.click("#checkResult details.signal summary");
check("A5 a signal expands to what / why / triggering part", await page.isVisible("#checkResult details.signal[open] dt >> text=Triggered by"));
check("A6 checks performed are listed", (await page.$$("#checkResult .check-item")).length === 3);
check("A7 precautions shown", await page.isVisible("#checkResult >> text=What you should do"));
const storedFirst = await api(`/api/finding/${first.id}`);
check("A8 the finding is private (anonymous read refused)", storedFirst.status === 401);

// 7–10: Police Portal shows the same finding
await page.goto(`${BASE}/#/login`);
await page.fill("#loginUser", USER);
await page.fill("#loginPass", PASS);
await page.click("form button[type=submit]");
await page.waitForSelector("#portalFindings", { timeout: 20000 }).catch(() => {});
await page.goto(`${BASE}/#/portal`);
await page.waitForSelector(`#portalFindings tr[data-finding="${first.id}"]`, { timeout: 20000 }).catch(() => {});
check("A9 portal 'All findings' lists the Checker finding", await page.isVisible(`#portalFindings tr[data-finding="${first.id}"]`));
const rowTag = await page.getAttribute(`#portalFindings tr[data-finding="${first.id}"] [data-tag]`, "data-tag").catch(() => null);
check("A10 portal row shows the same verdict", rowTag === first.tag, `${rowTag} vs ${first.tag}`);
await page.fill("#fQ", `adcb-secure-login-${RUN}`);
await page.selectOption("#fType", "url");
await page.click("#portalFindings button[type=submit]");
await page.waitForTimeout(400);
const filtered = await page.$$eval("#portalFindings tr[data-finding]", (rows) => rows.map((r) => r.dataset.finding));
check("A11 search + input-type filter finds exactly it", filtered.length === 1 && filtered[0] === String(first.id), JSON.stringify(filtered));
await page.click(`#portalFindings tr[data-finding="${first.id}"] a`);
await page.waitForSelector(".analysis", { timeout: 15000 });
const findingTag = await page.getAttribute(".analysis .verdict-hero [data-tag]", "data-tag").catch(() => null);
const stored = await api(`/api/finding/${first.id}`);
check("A12 finding page verdict = Checker verdict = stored tag",
  findingTag === first.tag && String(stored.body?.tag).toLowerCase() === first.tag, `${findingTag} / ${stored.body?.tag}`);
check("A13 finding page shows the same signals", (await page.$$(".analysis details.signal")).length === (stored.body?.signals || []).length);
check("A14 finding page shows authentication + verification + checks",
  await page.isVisible(".analysis >> text=Domain authentication") && await page.isVisible(".analysis >> text=Official-source verification")
  && (await page.$$(".analysis .check-item")).length === 3);

// 11–15: back to the Checker with a suspicious message
const second = await runCheck(MSG_IN);
check("A15 message check completes and is saved", Number.isFinite(second.id) && second.id > first.id, `#${second.id}`);
check("A16 message analysis shows message signals",
  await page.isVisible("#checkResult >> text=Demands a fee or payment") && await page.isVisible("#checkResult >> text=Parcel / delivery lure"));
check("A17 phone number removed from the stored message",
  !(await page.textContent("#checkResult .analysis")).includes("050 123 4567") && await page.isVisible("#checkResult >> text=[phone removed]"));
check("A18 link inside the message was analysed", await page.isVisible(`#checkResult >> text=emiratespost-${RUN}.top`));
await page.goto(`${BASE}/#/portal`);
await page.click("#portalFindings button[type=button]");     // reset filters
await page.waitForSelector(`#portalFindings tr[data-finding="${second.id}"]`, { timeout: 20000 }).catch(() => {});
check("A19 portal lists the second finding", await page.isVisible(`#portalFindings tr[data-finding="${second.id}"]`));

// Repeat after refreshing: both remain, nothing duplicated
const countBefore = (await api(`/api/portal/findings?q=${RUN}&limit=200`)).body?.total;
await page.reload();
await page.waitForSelector(`#portalFindings tr[data-finding="${second.id}"]`, { timeout: 20000 }).catch(() => {});
const countAfter = (await api(`/api/portal/findings?q=${RUN}&limit=200`)).body?.total;
check("A20 after reload both findings remain, no duplicates",
  await page.isVisible(`#portalFindings tr[data-finding="${first.id}"]`) && await page.isVisible(`#portalFindings tr[data-finding="${second.id}"]`)
  && countBefore === 2 && countAfter === 2, `${countBefore} → ${countAfter}`);
// re-checking the same message right away returns the same finding (no duplicate)
const again = await runCheck(MSG_IN);
check("A21 re-submitting the same message does not create a duplicate", again.id === second.id, `#${again.id}`);

// ---------------------------------------------------------------- B. validation, failure, AR, mobile
await page.goto(`${BASE}/#/check`);
await page.fill("#checkInput", "   ");
await page.click("#checkBtn");
check("B1 empty input → validation message, nothing sent", await page.isVisible("#checkError >> text=Enter a link"));
await page.fill("#checkInput", "javascript:alert(1)");
await page.click("#checkBtn");
check("B2 unsupported link → validation message", await page.isVisible("#checkError >> text=Only web links"));
await page.fill("#checkInput", "ftp://files.example.com/x");
await page.click("#checkBtn");
await page.waitForSelector("#checkResult [role=alert]", { timeout: 15000 }).catch(() => {});
check("B3 server-side rejection shown, no verdict", await page.isVisible("#checkError >> text=Only web links") && !(await page.isVisible("#checkResult .verdict-hero")));
await page.route("**/api/check", (route) => route.abort("connectionrefused"));
await page.fill("#checkInput", "https://example-unreachable.test/");
await page.click("#checkBtn");
await page.waitForSelector("#checkResult [role=alert]", { timeout: 15000 }).catch(() => {});
check("B4 backend unavailable → error, never a verdict",
  await page.isVisible("#checkResult >> text=can't be reached") && !(await page.isVisible("#checkResult .verdict-hero")));
await page.unroute("**/api/check");

await page.evaluate(() => localStorage.setItem("daggers.lang", "ar"));
await page.goto(`${BASE}/?lang=ar#/check`);
await page.click("#langSwitch button[data-lang=ar]").catch(() => {});
await page.waitForSelector("#checkInput");
const arMsg = `شرطة أبوظبي: تم تسجيل مخالفة عليك. ادفع الغرامة 500 درهم خلال 24 ساعة عبر الرابط https://adpolice-${RUN}.top/pay`;
await page.fill("#checkInput", arMsg);
await page.click("#checkBtn");
await page.waitForSelector("#checkResult .analysis", { timeout: 30000 }).catch(() => {});
const arTag = await page.getAttribute("#checkResult .verdict-hero [data-tag]", "data-tag").catch(() => null);
check("B5 Arabic message analysed with the Arabic UI", (await page.getAttribute("html", "dir")) === "rtl" && arTag === "fake", arTag);
check("B6 Arabic signal labels rendered", await page.isVisible("#checkResult >> text=يدّعي أنه جهة حكومية"));
await page.click("#langSwitch button[data-lang=en]").catch(() => {});

const mobile = await browser.newContext({ viewport: { width: 375, height: 760 }, isMobile: true, hasTouch: true });
const mp = await mobile.newPage();
await mp.goto(`${BASE}/#/check`);
await mp.fill("#checkInput", URL_IN);
await mp.click("#checkBtn");
await mp.waitForSelector("#checkResult .analysis", { timeout: 30000 }).catch(() => {});
const overflow = await mp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
check("B7 mobile (375px): result renders without horizontal overflow", (await mp.isVisible("#checkResult .analysis")) && overflow <= 1, `overflow ${overflow}px`);
await mobile.close();

// ---------------------------------------------------------------- C. investigation → report → AI
await page.goto(`${BASE}/#/portal`);
await page.waitForSelector("#invUrl", { timeout: 15000 }).catch(() => {});
await page.fill("#invUrl", `https://adcb-verify-${RUN}.xyz/login`);
await page.fill("#invText", "ICP announces visa amnesty for overstayers until 31 December 2026. Register today.");
await page.click("form:has(#invUrl) button[type=submit]");
await page.waitForURL(/#\/finding\/\d+/, { timeout: 20000 }).catch(() => {});
const invId = Number((page.url().match(/#\/finding\/(\d+)/) || [])[1]);
check("C1 investigation stored and opened", Number.isFinite(invId));
await page.click("text=File report").catch(() => {});
await page.waitForSelector("a[href^='#/portal/']", { timeout: 15000 }).catch(() => {});
const reportHref = await page.getAttribute("a[href^='#/portal/']", "href").catch(() => null);
check("C2 report filed from the finding page", !!reportHref, reportHref || "");
if (reportHref) {
  await page.goto(`${BASE}/${reportHref}`);
  await page.waitForSelector(".ai-panel button.btn-primary", { timeout: 15000 });
  await page.click(".ai-panel button.btn-primary");
  await page.waitForFunction(() => /Priority: P[12]/.test(document.querySelector(".ai-out")?.textContent || ""), null, { timeout: 45000 }).catch(() => {});
  const aiText = await page.textContent(".ai-out");
  const inv = await api(`/api/finding/${invId}`);
  check("C3 AI summary is evidence-structured and repeats the stored tag",
    /FACTS:/.test(aiText) && /MISSING:/.test(aiText) && aiText.includes(String(inv.body?.tag)));
}
check("C4 no uncaught page errors", errors.length === 0, errors.slice(0, 3).join(" | "));
await browser.close();

// ---------------------------------------------------------------- D. extension
const extDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "extension");
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "daggers-ext-"));
const SUSPECT = `https://adcb-secure-login-${RUN}.xyz/login`;
let ctx;
try {
  ctx = await chromium.launchPersistentContext(profile, {
    executablePath: EXEC, headless: true,
    args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  });
} catch (e) {
  check("D0 browser launched with the extension", false, String(e).slice(0, 120));
}
if (ctx) {
  await ctx.route("https://www.google.com/search*", (route) => route.fulfill({
    contentType: "text/html",
    body: `<!doctype html><html lang="en"><body><div id="search"><div id="rso">
      <div class="g"><a href="${SUSPECT}"><h3>ADCB login</h3></a></div>
      <div class="g"><a href="https://unknown-business.example/"><h3>Some business</h3></a></div>
      <div class="g"><a href="https://www.google.com/maps/place/x"><h3>Maps</h3></a></div>
    </div></div>
    <div id="tads"><a href="https://ad.example/"><h3>Sponsored</h3></a></div></body></html>`,
  }));
  const gp = await ctx.newPage();
  await gp.goto("https://www.google.com/search?q=adcb");
  await gp.waitForFunction(() => document.querySelectorAll(".daggers-tag:not(.daggers-tag--pending)").length >= 2, null, { timeout: 25000 }).catch(() => {});
  const labels = await gp.$$eval(".daggers-tag", (els) => els.map((e) => ({ text: e.textContent, prev: e.previousElementSibling?.getAttribute("href") })));
  const suspect = labels.find((l) => l.prev === SUSPECT);
  const scan = await (await fetch(`${BASE}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind: "url", input: SUSPECT, lang: "en" }) })).json();
  check("D1 extension labels organic results only", labels.length === 2, JSON.stringify(labels));
  check("D2 extension tag equals backend tag", suspect?.text === scan.tag, `${suspect?.text} vs ${scan.tag}`);
  check("D3 extension never labels the unknown site SAFE", !labels.some((l) => l.prev?.includes("unknown-business") && l.text === "SAFE"));
  await ctx.close();
}

const failed = results.filter((r) => !r.ok).length;
console.log(failed ? `✗ ${failed} of ${results.length} checks failed` : `✓ all ${results.length} browser checks passed`);
process.exit(failed ? 1 : 0);
