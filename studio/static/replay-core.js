/* Pure replay logic for the Trajectory drawer — NO DOM, NO module state. Everything the replay state
   machine decides (how long to dwell, how to accrue elapsed time, which stops exist, where to start,
   what's next) lives here as pure functions of explicit inputs, so it's unit-testable in isolation
   (the DOM + timer orchestration stays in app.js and calls these). UMD: a browser global + node require. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.ReplayCore = factory();
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const DWELL_FLOOR_MS = 50;        // a stop never dwells less than this (so a tiny turn still shows)
  const NOMINAL_REAL_MS = 1500;     // Init / no-live-timing stop's nominal "real" length (also speed-scaled)

  // the FAITHFUL real duration (ms) a stop represents: a turn → its real duration (when the trace has
  // live per-turn timing); otherwise a brief nominal length.
  function realMsFor(stop, iterations, perTurnTiming) {
    if (stop && stop.kind === "turn" && perTurnTiming)
      return Math.max(0, ((iterations || [])[stop.index] || {}).duration_s || 0) * 1000;
    return NOMINAL_REAL_MS;
  }

  // replay-ms to dwell on the REMAINING of a stop at `speed` — faithful: (real − elapsed) ÷ speed,
  // floored. Never negative (an over-consumed stop → the floor).
  function dwellMs(realMs, elapsed, speed) {
    return Math.max(DWELL_FLOOR_MS, Math.max(0, realMs - elapsed) / Math.max(1e-9, speed));
  }

  // real-ms consumed when `replayMs` of wall-clock elapses at `speed` (real = replay × speed), added to
  // the running elapsed. So a speed change / pause continues the REMAINING instead of restarting.
  function accrue(elapsed, replayMs, speed) {
    return elapsed + Math.max(0, replayMs) * speed;
  }

  // the walkable stops a replay steps through: Init, then every turn in order.
  function buildStops(iterations) {
    return [{ kind: "init", index: 0 }].concat(
      (iterations || []).map(function (it) { return { kind: "turn", index: it.index }; }));
  }

  // index of `sel` in `stops`, or -1 — e.g. a tool selection is not a walkable stop.
  function stopIndex(stops, sel) {
    return stops.findIndex(function (s) { return sel && s.kind === sel.kind && s.index === sel.index; });
  }

  // where play should START from the current selection: the selection itself if walkable; a TOOL → its
  // turn (so play still advances the whole run); else Init. (This is the start-from-tool fix at source.)
  function resolveStart(sel, timeline) {
    if (sel && sel.kind !== "tool") return { kind: sel.kind, index: sel.index };
    if (sel && sel.kind === "tool") {
      const ti = ((timeline || [])[sel.index] || {}).turn_index;
      if (ti != null) return { kind: "turn", index: ti };
    }
    return { kind: "init", index: 0 };
  }

  // the clamped prev/next stop from the current index (a tool selection → curIdx −1 → starts at Init).
  function stepTarget(stops, curIdx, dir) {
    const c = curIdx < 0 ? 0 : curIdx;
    return stops[Math.min(stops.length - 1, Math.max(0, c + dir))];
  }

  // the stop after `curIdx`, or null at the end / when off-list.
  function nextStop(stops, curIdx) {
    if (curIdx < 0 || curIdx >= stops.length - 1) return null;
    return stops[curIdx + 1];
  }

  return {
    DWELL_FLOOR_MS: DWELL_FLOOR_MS, NOMINAL_REAL_MS: NOMINAL_REAL_MS,
    realMsFor: realMsFor, dwellMs: dwellMs, accrue: accrue,
    buildStops: buildStops, stopIndex: stopIndex, resolveStart: resolveStart,
    stepTarget: stepTarget, nextStop: nextStop,
  };
});
