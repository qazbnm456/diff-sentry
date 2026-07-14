/* Static CSS contracts the zero-build frontend relies on (run: `node tests/static-contract.test.js`).
   These shipped broken once each, so they are pinned textually (no browser in the suite):
   1. the `[hidden]` guard — author `display:*` on a class otherwise beats the UA's
      `[hidden]{display:none}` and every JS `.hidden` toggle silently no-ops (all three mode panes
      rendered stacked; the trajectory handle showed before any run);
   2. the empty-stage glyph sizing — an inline SVG with only a viewBox inflates to the column width. */
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const css = fs.readFileSync(path.join(__dirname, "..", "static", "style.css"), "utf8");

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + e.message); }
}

test("[hidden] guard exists and is !important", () => {
  assert.match(css, /\[hidden\]\s*\{\s*display\s*:\s*none\s*!important\s*;?\s*\}/);
});

test("empty-stage glyph SVG has an explicit size", () => {
  const rule = css.match(/\.empty-stage \.es-glyph svg\s*\{([^}]*)\}/);
  assert.ok(rule, ".empty-stage .es-glyph svg rule is missing");
  assert.match(rule[1], /width\s*:/);
  assert.match(rule[1], /height\s*:/);
});

console.log(failed ? "\n" + failed + " test(s) FAILED" : "\nall passing");
process.exit(failed ? 1 : 0);
