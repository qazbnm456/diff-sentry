/* Pure, DOM-free decisions for the live-run driver — require-able + unit-tested (tests/run-core.test.js),
   loaded as a plain <script> before app.js (which reads the RunCore global, same as ReplayCore). Kept out
   of app.js so the terminal-outcome invariant — EVERY outcome finalizes the stage — has a test seam the
   DOM IIFE cannot give. The bug this guards: a 409/"kept" branch that set state but rendered nothing into
   the stage, leaving the animated "Classifying…" skeleton spinning forever. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.RunCore = factory();
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Classify one live-run attempt's terminal outcome → { status, stage, wroteResponse }.
  //   err         — null on a clean stream end (a `detection.run.completed` event already carried the
  //                 response); `{status: 409}` when a finalized run already owns this id; else any thrown
  //                 error (network drop / HTTP 5xx).
  //   finalStatus — the status carried by the completed event (used only on the clean-end path).
  // `stage` is NEVER null — that is exactly the invariant the skeleton-hang bug violated:
  //   "card"      the completed event already produced the result; the caller re-GETs + renders the card
  //   "existing"  this id already had a finalized run — the 409 case; app.js prompts overwrite-or-keep
  //   "failed"    render a failed stage card (clears the "Classifying…" skeleton)
  // `wroteResponse` — a durable response now exists for this id (a completion, or a pre-existing 409).
  function planTerminal(err, finalStatus) {
    if (!err) return { status: finalStatus, stage: "card", wroteResponse: true };
    if (err.status === 409) return { status: "kept", stage: "existing", wroteResponse: true };
    return { status: "failed", stage: "failed", wroteResponse: false };
  }

  // Decide what the stage's Change view renders → { kind: "files"|"body"|"trace"|"loading"|"gone",
  // fetch? }. `change` is the client-held pasted payload (null for pr/issue AND replayed runs — their
  // diff never reaches the client); `traceChange` is the run_start `event` fetched from /iterations:
  //   undefined      not asked yet → kind "loading" with fetch:true (fires exactly once)
  //   null           fetch in flight → "loading", no refire
  //   string         the normalized untrusted change the planner saw → "trace"
  //   {error:true}   a TRANSIENT fetch failure → "error" (terminal + honest; re-loading the run retries
  //                  on a fresh object — never silently claim the trace is gone)
  //   false / ""     the trace genuinely has no readable event (404 / empty) → "gone"
  // The invariant this guards: the view can never WEDGE on "loading" — every value maps to a terminal
  // kind or to the single fetch that will produce one.
  function planChangeView(change, traceChange) {
    if (change && change.files && change.files.length) return { kind: "files" };
    if (change && change.body) return { kind: "body" };
    if (traceChange === undefined || traceChange === null) {
      return { kind: "loading", fetch: traceChange === undefined };
    }
    if (typeof traceChange === "string" && traceChange) return { kind: "trace" };
    if (traceChange && traceChange.error) return { kind: "error" };
    return { kind: "gone" };
  }

  return { planTerminal: planTerminal, planChangeView: planChangeView };
});
