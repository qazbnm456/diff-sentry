/* Unit tests for the pure replay core (run: `node tests/replay-core.test.js`). Node 16 lacks the
   built-in test runner, so this is a tiny assert-based harness that exits non-zero on any failure. */
"use strict";
const assert = require("assert");
const RC = require("../static/replay-core.js");

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + e.message); }
}

// ---- the timing math (the resume / speed-change correctness the churn was about) ----
test("dwellMs: faithful (real − elapsed) ÷ speed", () => {
  assert.strictEqual(RC.dwellMs(38000, 0, 2), 19000);       // 38s real at 2× → 19s dwell
  assert.strictEqual(RC.dwellMs(38000, 20000, 4), 4500);    // 20s consumed → 18s left at 4× → 4.5s
  assert.strictEqual(RC.dwellMs(38000, 0, 1), 38000);       // 1× → real time
});
test("dwellMs: floored, never negative", () => {
  assert.strictEqual(RC.dwellMs(100, 0, 64), RC.DWELL_FLOOR_MS);     // tiny turn → floor
  assert.strictEqual(RC.dwellMs(1000, 5000, 2), RC.DWELL_FLOOR_MS);  // over-consumed → floor, not < 0
});
test("accrue: elapsed += replayMs × speed (continues, not restart)", () => {
  assert.strictEqual(RC.accrue(0, 10000, 2), 20000);        // 10s played at 2× → 20s real consumed
  assert.strictEqual(RC.accrue(20000, 5000, 4), 40000);     // then 5s at 4× → +20s
  assert.strictEqual(RC.accrue(100, -50, 2), 100);          // clock skew → no negative accrual
});
test("realMsFor: turn → real duration (only when live); else nominal", () => {
  const its = [{ index: 0, duration_s: 5 }, { index: 1, duration_s: 0 }];
  assert.strictEqual(RC.realMsFor({ kind: "turn", index: 0 }, its, true), 5000);
  assert.strictEqual(RC.realMsFor({ kind: "turn", index: 1 }, its, true), 0);          // 0-dur turn
  assert.strictEqual(RC.realMsFor({ kind: "turn", index: 0 }, its, false), RC.NOMINAL_REAL_MS); // no live ts
  assert.strictEqual(RC.realMsFor({ kind: "init", index: 0 }, its, true), RC.NOMINAL_REAL_MS);
});

// ---- the stop walk / start resolution (the state-sync bugs were here) ----
test("buildStops + stopIndex: Init + turns; a tool is not a stop", () => {
  const stops = RC.buildStops([{ index: 0 }, { index: 1 }, { index: 2 }]);
  assert.deepStrictEqual(stops, [
    { kind: "init", index: 0 }, { kind: "turn", index: 0 },
    { kind: "turn", index: 1 }, { kind: "turn", index: 2 }]);
  assert.strictEqual(RC.stopIndex(stops, { kind: "turn", index: 1 }), 2);
  assert.strictEqual(RC.stopIndex(stops, { kind: "tool", index: 5 }), -1);   // a tool isn't walkable
  assert.strictEqual(RC.stopIndex(stops, null), -1);
});
test("resolveStart: tool → its turn (the start-from-tool fix), turn/init → itself, else Init", () => {
  const tl = [{ turn_index: 3 }, {}];
  assert.deepStrictEqual(RC.resolveStart({ kind: "tool", index: 0 }, tl), { kind: "turn", index: 3 });
  assert.deepStrictEqual(RC.resolveStart({ kind: "tool", index: 1 }, tl), { kind: "init", index: 0 }); // no turn_index
  assert.deepStrictEqual(RC.resolveStart({ kind: "turn", index: 2 }, tl), { kind: "turn", index: 2 });
  assert.deepStrictEqual(RC.resolveStart(null, tl), { kind: "init", index: 0 });
});
test("stepTarget: clamped prev/next; a tool (curIdx −1) starts from Init", () => {
  const stops = RC.buildStops([{ index: 0 }, { index: 1 }]);   // [init, t0, t1]
  assert.deepStrictEqual(RC.stepTarget(stops, 0, 1), { kind: "turn", index: 0 });   // init → t0
  assert.deepStrictEqual(RC.stepTarget(stops, 2, 1), { kind: "turn", index: 1 });   // last → clamp
  assert.deepStrictEqual(RC.stepTarget(stops, 0, -1), { kind: "init", index: 0 });  // init → clamp
  assert.deepStrictEqual(RC.stepTarget(stops, -1, 1), { kind: "turn", index: 0 });  // tool → treat as Init, step
});
test("nextStop: advance, or null at the end / off-list", () => {
  const stops = RC.buildStops([{ index: 0 }]);   // [init, t0]
  assert.deepStrictEqual(RC.nextStop(stops, 0), { kind: "turn", index: 0 });
  assert.strictEqual(RC.nextStop(stops, 1), null);    // last → end
  assert.strictEqual(RC.nextStop(stops, -1), null);   // off-list (would have stalled the replay) → end
});

console.log(failed ? "\n" + failed + " test(s) FAILED" : "\nall passing");
process.exit(failed ? 1 : 0);
