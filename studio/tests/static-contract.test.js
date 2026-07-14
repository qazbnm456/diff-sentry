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

test("the grid owns the viewport height and the meta column is its own scroll track", () => {
  assert.match(css, /\.layout\s*\{[^}]*height\s*:\s*calc\(100vh - 56px\)/);
  const meta = css.match(/(^|\n)\.meta-col\s*\{([^}]*)\}/);
  assert.ok(meta, "base .meta-col rule is missing");
  assert.match(meta[2], /overflow-y\s*:\s*auto/);
});

test("meta modules are pinned at content height inside the scrolling column", () => {
  // overflow:hidden flips a flex item's automatic min-size to 0: without this pin the fixed-height
  // column COMPRESSES every module to fit (content crushed) instead of scrolling.
  const rule = css.match(/(^|\n)\.meta-col \.module\s*\{([^}]*)\}/);
  assert.ok(rule && /flex-shrink\s*:\s*0|flex\s*:\s*none/.test(rule[2]),
    ".meta-col .module must not compress inside the scroll column");
});

test("attacker-length tokens wrap in the meta modules (module overflow:hidden clips them otherwise)", () => {
  const prose = css.match(/(^|\n)\.prose\s*\{([^}]*)\}/);
  assert.ok(prose && /word-break|overflow-wrap/.test(prose[2]), ".prose must wrap long tokens");
  const tchip = css.match(/(^|\n)\.tchip\s*\{([^}]*)\}/);
  assert.ok(tchip && /word-break|overflow-wrap/.test(tchip[2]), ".tchip must wrap long tokens");
});

console.log(failed ? "\n" + failed + " test(s) FAILED" : "\nall passing");
process.exit(failed ? 1 : 0);
