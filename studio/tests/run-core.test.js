/* Unit tests for the pure run-driver core (run: `node tests/run-core.test.js`). Node 16 lacks the
   built-in test runner, so this is a tiny assert-based harness that exits non-zero on any failure. */
"use strict";
const assert = require("assert");
const RC = require("../static/run-core.js");

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + e.message); }
}

// ---- planTerminal: every terminal outcome maps to a stage-finalizing action (the skeleton-hang guard) ----
test("clean end → 'card' (the completed event already drew the stage), response written", () => {
  assert.deepStrictEqual(RC.planTerminal(null, "complete"),
    { status: "complete", stage: "card", wroteResponse: true });
});
test("409 → show the EXISTING stored run as 'kept'; a response exists → mark already_done", () => {
  assert.deepStrictEqual(RC.planTerminal({ status: 409 }, "failed"),
    { status: "kept", stage: "existing", wroteResponse: true });
});
test("other error (network / 5xx) → clear the skeleton via a failed stage; no response written", () => {
  assert.deepStrictEqual(RC.planTerminal(new Error("boom"), "failed"),
    { status: "failed", stage: "failed", wroteResponse: false });
  assert.deepStrictEqual(RC.planTerminal({ status: 500 }, "failed"),
    { status: "failed", stage: "failed", wroteResponse: false });
});
test("INVARIANT: EVERY outcome finalizes the stage (the bug was a branch that finalized nothing)", () => {
  const outcomes = [null, { status: 409 }, { status: 500 }, { status: 503 },
                    new Error("x"), { status: 409, message: "y" }, {}];
  for (const err of outcomes) {
    const p = RC.planTerminal(err, "complete");
    assert.ok(["card", "existing", "failed"].includes(p.stage),
      "stage must be a finalizing action for outcome " + JSON.stringify(err));
  }
});

// ---- planChangeView: the Change view can never wedge on "loading" (the pr/issue trace fallback) ----
test("a pasted payload with files renders the per-file diff, whatever the trace state", () => {
  assert.equal(RC.planChangeView({ files: [{}] }, undefined).kind, "files");
  assert.equal(RC.planChangeView({ files: [{}] }, "trace text").kind, "files");
});
test("a pasted body (an issue) renders the body", () => {
  assert.equal(RC.planChangeView({ body: "issue body" }, undefined).kind, "body");
});
test("no client change + never asked → loading, and fetch fires exactly on this state", () => {
  assert.deepStrictEqual(RC.planChangeView(null, undefined), { kind: "loading", fetch: true });
});
test("fetch in flight → still loading, but never refires", () => {
  assert.deepStrictEqual(RC.planChangeView(null, null), { kind: "loading", fetch: false });
});
test("the fetched run_start event renders as the trace view", () => {
  assert.equal(RC.planChangeView(null, '{"_diff_sentry_metadata": …}').kind, "trace");
});
test("a gone trace or an empty event is TERMINAL, never an infinite loading", () => {
  assert.equal(RC.planChangeView(null, false).kind, "gone");
  assert.equal(RC.planChangeView(null, "").kind, "gone");
});
test("a transient fetch failure is its own honest terminal state — never claimed as a gone trace", () => {
  assert.equal(RC.planChangeView(null, { error: true }).kind, "error");
});

console.log(failed ? "\n" + failed + " test(s) FAILED" : "\nall passing");
process.exit(failed ? 1 : 0);
