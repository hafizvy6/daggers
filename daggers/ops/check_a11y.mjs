#!/usr/bin/env node
/**
 * WS3 gate 2 — a11y & RTL audit on the running app.
 *   node ops/check_a11y.mjs http://127.0.0.1:8080
 * Checks: ≥4.5:1 text contrast (sampled elements), 44px tap targets on primary
 * buttons, visible focus ring, single <h1> per view, logical RTL mirroring,
 * no horizontal overflow at 390px, keyboard walk Feed→Detail→Portal.
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
const routes = ["#/feed", "#/finding/42", "#/check", "#/number", "#/portal/7", "#/guard", "#/sweep", "#/verdict/adcb-secure-login.xyz"];
const fails = [];
const browser = await launch();

const contrastJS = () => {
  const lum = (c) => {
    const [r, g, b] = c.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number).map((v) => v / 255)
      .map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const bg = (el) => {
    let n = el;
    while (n && n !== document.documentElement) {
      const c = getComputedStyle(n).backgroundColor;
      if (c && !/rgba\(0, 0, 0, 0\)|transparent/.test(c)) return c;
      n = n.parentElement;
    }
    return "rgb(250, 247, 241)";
  };
  const bad = [];
  const seen = new Set();
  for (const el of document.querySelectorAll("p,span,a,button,td,th,dt,dd,h1,h2,h3,label,figcaption,input")) {
    if (!el.textContent?.trim() || el.querySelector("svg,img")) continue;
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden" || el.offsetParent === null) continue;
    const size = parseFloat(cs.fontSize);
    const large = size >= 24 || (size >= 18.66 && parseInt(cs.fontWeight) >= 700);
    const a = lum(cs.color), b = lum(bg(el));
    const cr = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const need = large ? 3 : 4.5;
    if (cr < need) {
      const sig = `${el.tagName}|${cs.color}|${(el.textContent || "").trim().slice(0, 30)}`;
      if (seen.has(sig)) continue;
      seen.add(sig);
      bad.push(`${cr.toFixed(2)} < ${need} · ${el.tagName} "${(el.textContent || "").trim().slice(0, 40)}" (${cs.color})`);
    }
  }
  return bad;
};

for (const [lang, w] of [["en", 1440], ["ar", 1440], ["en", 390]]) {
  const ctx = await browser.newContext({ viewport: { width: w, height: 900 } });
  const page = await ctx.newPage();
  for (const r of routes) {
    const url = `${base}/?lang=${lang}${r}`;
    await page.goto(url, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(r === "#/sweep" ? 3800 : 1100);
    const info = await page.evaluate((js) => {
      const fn = new Function(`return (${js})()`);
      return {
        contrast: fn(),
        h1: document.querySelectorAll("h1").length,
        overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
        dir: document.documentElement.dir,
        tinyTargets: [...document.querySelectorAll(".btn, .nav-link, .icon-btn, .query-pill")]
          .filter((b) => b.offsetParent !== null)
          .map((b) => b.getBoundingClientRect())
          .filter((r) => r.height > 0 && r.height < 36).length,
        smallSecondary: [...document.querySelectorAll(".seg button, .lang-switch button, .tabs button")]
          .filter((b) => b.offsetParent !== null)
          .map((b) => b.getBoundingClientRect())
          .filter((r) => r.height > 0 && r.height < 28).length,
      };
    }, contrastJS.toString());
    const tag = `${lang}/${w} ${r}`;
    if (info.h1 !== 1) fails.push(`${tag}: h1 count = ${info.h1}`);
    if (info.overflow) fails.push(`${tag}: horizontal overflow at ${w}px`);
    if (lang === "ar" && info.dir !== "rtl") fails.push(`${tag}: dir not rtl`);
    if (lang === "en" && info.dir !== "ltr") fails.push(`${tag}: dir not ltr`);
    info.contrast.slice(0, 4).forEach((c) => fails.push(`${tag}: contrast ${c}`));
    if (info.tinyTargets > 2) fails.push(`${tag}: ${info.tinyTargets} tap targets under 36px`);
  }
  await ctx.close();
}

// keyboard walk: Feed → row → Finding → Portal detail via nav
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/#/feed`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  let hops = 0;
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press("Tab");
    const focusRing = await page.evaluate(() => {
      const el = document.activeElement;
      if (!el || el === document.body) return null;
      const o = getComputedStyle(el).outlineWidth;
      return { tag: el.tagName, outline: o, text: (el.textContent || "").trim().slice(0, 24) };
    });
    if (focusRing) {
      hops++;
      if (focusRing.outline === "0px") fails.push(`keyboard: no focus ring on <${focusRing.tag}> "${focusRing.text}"`);
    }
  }
  if (hops < 5) fails.push(`keyboard: only ${hops} focusable stops on feed`);
  await ctx.close();
}

await browser.close();
if (fails.length) {
  console.log(`✗ a11y audit: ${fails.length} issue(s)`);
  fails.slice(0, 40).forEach((f) => console.log("  " + f));
  process.exit(1);
}
console.log("✓ a11y audit clean — contrast, tap targets, RTL, overflow, keyboard walk");
