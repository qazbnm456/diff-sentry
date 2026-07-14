"""Build a structured per-iteration breakdown of a run from its trace — the data behind the studio's
Trajectory drawer — plus the read-time evidence derivations the response envelope omits. Pure functions
(no web deps), unit-tested independently of the server.

An RLM run is a sequence of `main_step` REPL turns (the planner's reasoning + the Python code it ran +
that code's output). The `tool_call` / `sub_call` events that follow a turn (scan / classify / fetch /
skill / analyst) belong to that turn — its code invoked them. We GROUP them per turn, carry the
`run_start` meta as the run's INITIAL state (the change / instructions / models / budgets), and attribute
wall-clock time from the event `ts` deltas (no per-call instrumentation exists, so the gap between
consecutive events is the only signal of where the time went).

`cited_unknown_ids` reconstructs the fabrication tell — indicator ids the planner CITED that match no
recorded hit — from the trace. `assemble.AssembledVerdict` carries it, but `DetectionResponse` does not,
so the studio re-derives it here (pure over the frozen trace/v1 contract; works replay-only, no
diff_sentry import). This mirrors `assemble.assemble_verdict` (the union is baseline ∪ scan hits).
"""

from __future__ import annotations

from typing import Any, Optional

_CAP = 16000   # per-field char cap — generous (rarely hit); bounds a pathological output/blob


def _step_key(e: dict) -> int:
    s = str(e.get("step_id", ""))
    return int(s) if s.lstrip("-").isdigit() else 1 << 30


def _preview(s: Any) -> Optional[str]:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= _CAP else s[:_CAP] + "\n…[truncated — full text in the trace]"


def _gap(ts: Optional[float], prev: Optional[float]) -> Optional[float]:
    return round(ts - prev, 3) if (ts is not None and prev is not None) else None


def _tool_entry(p: dict, gap: Optional[float]) -> dict:
    """One tool_call → a UI-ready entry: a label, the input it was given, the output it returned."""
    tool = p.get("tool")
    args = p.get("args") or {}
    e: dict = {"kind": "tool", "tool": tool, "ok": p.get("ok"), "duration_s": gap}
    if tool == "scan_indicators":
        hits = p.get("hits") or []
        e.update(label="scan", target=_preview(args.get("region")), n=p.get("n") or len(hits),
                 hits=[{"id": h.get("id"), "rule": h.get("rule"), "severity": h.get("severity"),
                        "title": h.get("title"), "evidence": h.get("evidence"),
                        "location": h.get("location"), "decoded": h.get("decoded")}
                       for h in hits if isinstance(h, dict)])
    elif tool == "deep_classify":
        e.update(label="classify", verdict=p.get("verdict"), confidence=p.get("confidence"),
                 circuit_broken=bool(p.get("circuit_broken")), error=p.get("error"),
                 errors=p.get("errors") or [], findings=_preview(args.get("findings")),
                 output=_preview(p.get("raw")))
    elif tool == "fetch_url":
        e.update(label="fetch", target=args.get("url"), status=p.get("status"),
                 bytes=p.get("bytes"), note=p.get("note"), content=_preview(p.get("preview")))
    elif tool == "read_skill":
        e.update(label="skill", target=args.get("name"), result_len=p.get("result_len"),
                 content=_preview(p.get("preview")))
    elif tool == "list_skills":
        e.update(label="skill", target="(catalog)", content=_preview(p.get("result")))
    else:
        e.update(label=tool or "tool", target=_preview(args))
    return e


def _sub_entry(p: dict, gap: Optional[float]) -> dict:
    """One sub_call (an analyst escalation) → the distilled question + the answer it returned."""
    return {"kind": "analyst", "label": "analyst", "model": p.get("name") or p.get("model"),
            "duration_s": gap, "input": _preview(p.get("input")),
            "output": _preview(p.get("processed") or p.get("raw")), "error": p.get("error")}


def _hit_ids_from_trace(events: list[dict]) -> set:
    """The UNION of every recorded deterministic hit id — run_start meta `baseline_indicators` ∪ every
    `scan_indicators` tool_call's `hits`. Mirrors `diff_sentry.indicators.hits_from_events` (pure)."""
    ids: set = set()

    def _absorb(raw) -> None:
        for h in raw or []:
            if isinstance(h, dict) and h.get("id"):
                ids.add(h["id"])

    for e in events:
        p = e.get("payload") or {}
        if e.get("type") == "run_start":
            _absorb((p.get("meta") or {}).get("baseline_indicators"))
        elif e.get("type") == "tool_call" and p.get("tool") == "scan_indicators":
            _absorb(p.get("hits"))
    return ids


def cited_unknown_ids(events: list[dict]) -> list[str]:
    """The planner's cited `indicator_ids` that match NO recorded hit — a fabrication tell. Re-derived
    from the trace because `DetectionResponse` omits it (see module docstring). Empty when no result."""
    cited: list[str] = []
    for e in reversed(events):
        if e.get("type") == "result":
            out = (e.get("payload") or {}).get("output")
            if isinstance(out, dict):
                cited = [str(c) for c in (out.get("indicator_ids") or [])]
            break
    known = _hit_ids_from_trace(events)
    return [c for c in cited if c not in known]


def build_iterations(events: list[dict]) -> dict:
    """Decompose a run's trace into the Trajectory data. Returns
    `{started_at, total_s, timing_note, per_turn_timing, initial:{…}, iterations:[…], timeline:[…]}`.

    TWO views:
    - `iterations` — the planner's REPL turns (reasoning + code + its output), in turn order. CONTENT is
      always reliable; each turn's `output` already contains its tools' results inline. Per-turn timing
      (`rel_s`/`duration_s`) is attached WHEN the trace carries live `main_step` ts (rlm-kit backfills
      them as each turn is parsed → `per_turn_timing=True`). An OLDER trace flushed every `main_step` at
      finalize, so their ts cluster at one instant; we detect that, set `per_turn_timing=False`, and skip
      per-turn durations rather than fake them.
    - `timeline` — the `tool_call`/`sub_call` events, ALWAYS recorded LIVE with real `ts`. Each entry
      carries `rel_s` (since run start) and `duration_s` (the gap since the previous live event). The
      accurate "where did the time go" signal either way, and the headline for debugging a slow run.
    """
    evs = sorted(events, key=_step_key)
    meta: dict = {}
    ts0: Optional[float] = None
    for e in evs:
        if e.get("type") == "run_start":
            meta = (e.get("payload") or {}).get("meta") or {}
            ts0 = e.get("ts")
            break
    ts_end: Optional[float] = None
    for e in reversed(evs):
        if e.get("type") in ("run_end", "result", "final"):
            ts_end = e.get("ts")
            break

    iterations: list[dict] = []
    for e in evs:
        if e.get("type") == "main_step":
            p = e.get("payload") or {}
            iterations.append({"turn": p.get("turn"), "reasoning": _preview(p.get("reasoning")),
                               "code": _preview(p.get("code")), "output": _preview(p.get("output")),
                               "_ts": e.get("ts")})
    iterations.sort(key=lambda it: it["turn"] if it["turn"] is not None else 1 << 30)
    # Per-turn timing is available IFF the trace carries live main_step ts (rlm-kit backfills them as each
    # turn is parsed). An older trace flushed every main_step at finalize, so their ts cluster at one
    # instant (span ~0) — detect that and skip per-turn timing (the tool timeline still carries the real
    # where-did-time-go signal). A >1s span over ≥2 turns can only be live (an LM turn is seconds+).
    step_ts = [it["_ts"] for it in iterations if isinstance(it["_ts"], (int, float))]
    per_turn = len(step_ts) >= 2 and (max(step_ts) - min(step_ts)) > 1.0
    for i, it in enumerate(iterations):
        it["index"] = i
        if per_turn and isinstance(it["_ts"], (int, float)):
            it["rel_s"] = round(it["_ts"] - ts0, 3) if ts0 is not None else None
            nxt = iterations[i + 1]["_ts"] if i + 1 < len(iterations) else ts_end   # last turn → run end
            it["duration_s"] = round(nxt - it["_ts"], 3) if isinstance(nxt, (int, float)) else None
        it.pop("_ts", None)

    timeline: list[dict] = []
    prev = ts0
    for e in evs:
        t = e.get("type")
        ts = e.get("ts")
        if t not in ("tool_call", "sub_call") or ts is None:
            continue
        p = e.get("payload") or {}
        entry = _tool_entry(p, _gap(ts, prev)) if t == "tool_call" else _sub_entry(p, _gap(ts, prev))
        entry["seq"] = len(timeline)
        entry["rel_s"] = round(ts - ts0, 3) if ts0 is not None else None
        timeline.append(entry)
        prev = ts

    # Map each tool/analyst call to the TURN whose code produced it — ONLY when per-turn timing is live
    # (else main_step ts cluster at finalize and the mapping is meaningless). A turn's code runs AFTER its
    # parse (the main_step rel_s) and before the next turn's, so a call belongs to the turn with the
    # greatest main_step rel_s ≤ the call's rel_s. `turn_index` indexes `iterations`.
    if per_turn:
        marks = sorted((it["rel_s"], it["index"]) for it in iterations
                       if isinstance(it.get("rel_s"), (int, float)))
        for entry in timeline:
            r = entry.get("rel_s")
            if r is None or not marks:
                continue
            assigned = marks[0][1]
            for mrel, midx in marks:
                if mrel <= r:
                    assigned = midx
                else:
                    break
            entry["turn_index"] = assigned

    # diff-sentry records the run's first input as `event` (the normalized untrusted change string); its
    # derived summary is `source` (repo/kind/number/author/title). Surface both for the Init pane.
    change = meta.get("event")
    initial = {
        "change": _preview(change),
        "source": meta.get("source"),
        "instructions": _preview(meta.get("instructions")),
        "change_chars": len(change) if isinstance(change, str) else None,
        "models": {k: meta.get(k) for k in ("planner", "analyst", "classifier")},
        "baseline_indicators": meta.get("baseline_indicators") or [],
        "emit_on": meta.get("emit_on"),
        "max_iterations": meta.get("max_iterations"),
        "max_llm_calls": meta.get("max_llm_calls"),
    }
    total = round(ts_end - ts0, 3) if (ts_end is not None and ts0 is not None) else None
    note = ("Per-turn timing is live — captured as each turn was parsed; the tool timeline shows where "
            "time went within the turns."
            if per_turn else
            "Per-turn timing isn't available for this trace (turns weren't live-stamped, or the run was "
            "too short to span); the timeline carries the live tool/analyst calls — where time went.")
    return {"started_at": ts0, "total_s": total, "timing_note": note, "per_turn_timing": per_turn,
            "initial": initial, "iterations": iterations, "timeline": timeline}
