/* Contract tests for the trajectory drawer FACTORY (run: `node tests/trajectory.test.js`). trajectory.js
   is a DOM factory, not a pure core, so we stub a minimal DOM and assert the dependency-injection
   contract: building it runs every create/wiring path without a ReferenceError (a missing injected dep
   would throw here, which app.js's node --check cannot catch), the facade shape is stable, and the live
   getRunId/isBusy getters are actually consulted. Same tiny assert harness as run-core.test.js. */
"use strict";
const assert = require("assert");

// --- minimal stub DOM: $ caches by selector so a test can observe the same element the factory holds ---
global.window = {};
global.document = { addEventListener() {} };
global.performance = { now: () => 0 };
global.requestAnimationFrame = (f) => f();
global.ReplayCore = require("../static/replay-core.js"); // trajectory reads the global ReplayCore

function el() {
  return {
    hidden: false, textContent: "", innerHTML: "", value: "", scrollTop: 0, offsetWidth: 0,
    dataset: {}, style: {},
    addEventListener() {}, setAttribute() {}, removeAttribute() {}, focus() {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    querySelector() { return el(); }, querySelectorAll() { return []; },
    getBoundingClientRect() { return { left: 0, width: 0, top: 0, right: 0 }; },
    scrollTo() {}, scrollIntoView() {}, closest() { return null; },
  };
}
require("../static/trajectory.js"); // sets window.Trajectory

function make(over) {
  const els = {};
  const $ = (sel) => els[sel] || (els[sel] = el());
  const deps = Object.assign({
    $, esc: (s) => String(s == null ? "" : s), feedError() {}, ICONS: {},
    fmtBytes: () => "", tint: (s) => s, formatElapsed: () => "", _linkify: (s) => s,
    getRunId: () => "run-1", isBusy: () => false,
  }, over || {});
  return { t: window.Trajectory(deps), $ };
}

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + e.message); }
}

test("build + wiring run without a ReferenceError (the missing-injected-dep guard)", () => {
  const { t } = make();
  assert.ok(t, "factory returned nothing");
});
test("facade shape is exactly { open, refreshTransport, reset, showHandle }", () => {
  const { t } = make();
  assert.deepStrictEqual(Object.keys(t).sort(), ["open", "refreshTransport", "reset", "showHandle"]);
  ["open", "reset", "showHandle", "refreshTransport"].forEach((k) => assert.strictEqual(typeof t[k], "function", k));
});
test("refreshTransport is on the facade and callable (app.js setBusy() calls it — a missing facade "
   + "entry was a ReferenceError that hung every load/classify on the skeleton)", () => {
  const { t } = make();
  assert.strictEqual(typeof t.refreshTransport, "function");
  t.refreshTransport();   // must not throw
});
test("showHandle consults the injected getRunId: reveals the handle only when a run id exists", () => {
  const withRun = make({ getRunId: () => "run-1" });
  const h1 = withRun.$("#traj-handle"); h1.hidden = true;
  withRun.t.showHandle();
  assert.strictEqual(h1.hidden, false, "handle should be revealed when getRunId() is truthy");

  const noRun = make({ getRunId: () => null });
  const h2 = noRun.$("#traj-handle"); h2.hidden = true;
  noRun.t.showHandle();
  assert.strictEqual(h2.hidden, true, "handle should stay hidden when getRunId() is empty");
});
test("reset hides the handle and runs its stop/close paths without throwing", () => {
  const { t, $ } = make();
  const h = $("#traj-handle"); h.hidden = false;
  t.reset();
  assert.strictEqual(h.hidden, true, "reset should hide the handle");
});

console.log(failed ? "\n" + failed + " test(s) FAILED" : "\nall passing");
process.exit(failed ? 1 : 0);
