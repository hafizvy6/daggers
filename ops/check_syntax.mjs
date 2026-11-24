#!/usr/bin/env node
/**
 * Parse every ES module in web/js without executing it.
 * Wraps the file in an async IIFE (so top-level await/return are legal) and
 * neutralises import/export lines. Any real syntax error still throws with a
 * file path + line, which is the whole point of this check.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

const root = new URL("../web/js/", import.meta.url).pathname;
const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (name.endsWith(".js")) files.push(p);
  }
})(root);

function wrap(src) {
  const body = src
    .replace(/^\s*import\s[^;]*;?\s*$/gm, "")
    .replace(/^\s*import\s*{[\s\S]*?}\s*from\s*["'][^"']+["'];?\s*$/gm, "")
    .replace(/\bexport\s+default\s+/g, "const __default__ = ")
    .replace(/\bexport\s+(async\s+function|function|class|const|let|var)\b/g, "$1")
    .replace(/\bexport\s*{[^}]*}\s*;?/g, "")
    .replace(/import\.meta/g, "({ url: 'file:///x' })")
    .replace(/<\/script>/g, "<\\/script>");   // avoid HTML-parse surprises
  return `(async () => {\n${body}\n})`;
}

let bad = 0;
for (const f of files) {
  try {
    new vm.Script(wrap(readFileSync(f, "utf8")), { filename: f });
  } catch (err) {
    bad++;
    console.error(`✗ ${f.replace(root, "")}: ${err.message}`);
  }
}
if (bad) { console.log(`✗ syntax: ${bad} file(s) failed to parse`); process.exit(1); }
console.log(`✓ syntax — ${files.length} ES modules parse cleanly`);
