"""Map a diff-sentry trace event → a public SSE event (the single source of truth for the streamed
event surface). Pure function, no web deps — unit-tested independently of the server.

A trace event is `{type, step_id, ts, payload}` (rlm-kit's frozen trace/v1). We surface only the events
a UI needs and rename them to a stable `detection.<noun>.<verb>` vocabulary (OpenAI-Responses-flavored).
Unknown / internal events return None (skipped). The full structured result is NOT streamed — the client
GETs `/v1/runs/{run_id}` after `detection.run.completed`.

Payload tolerance is deliberate (the tools emit shape variants — see `diff_sentry.deep_classify`):
`deep_classify` records THREE shapes — validated (`ok`/`verdict`/`confidence`), circuit-break
(`ok=False, circuit_broken=True`), and endpoint-error (ONLY `error`, no `ok` key). We normalize all
three. `sub_call` carries `input`/`processed`/`raw` (rlm-kit's sub-LM), not question/answer.
"""

from __future__ import annotations

from typing import Any, Optional

_ROLES = ("planner", "analyst", "classifier")
_SEV_ORDER = ("info", "low", "medium", "high", "critical")


def _worst_severity(hits) -> Optional[str]:
    """The highest severity across recorded indicator hits (a list of dicts), or None when empty."""
    best, best_rank = None, -1
    for h in hits or []:
        sev = (h.get("severity") if isinstance(h, dict) else "") or ""
        try:
            rank = _SEV_ORDER.index(sev.strip().lower())
        except ValueError:
            continue
        if rank > best_rank:
            best, best_rank = sev.strip().lower(), rank
    return best


def to_event(trace_event: dict) -> Optional[dict[str, Any]]:
    """Return `{"event": <name>, "data": {...}}` for a surfaced trace event, else None."""
    t = trace_event.get("type")
    p = trace_event.get("payload") or {}

    if t == "run_start":
        meta = p.get("meta") or {}
        return _ev("detection.run.created", {
            "models": {k: meta[k] for k in _ROLES if meta.get(k)},
            "source": meta.get("source"),          # the change under review (repo/kind/number/author/title)
            "baseline": len(meta.get("baseline_indicators") or []),   # host-side hits already in the trace
        })
    if t == "main_step":
        # Surfaced for the REPLAY (step-sorted) stream. The LIVE endpoint's sink drops main_step (it
        # flushes post-hoc, so it would arrive as a trailing burst — see live.trace_event_sink).
        return _ev("detection.plan.step", {
            "turn": p.get("turn"),
            "reasoning": p.get("reasoning"),
            "has_code": bool(p.get("code")),
        })
    if t == "sub_call":
        return _ev("detection.analyst.escalation", {
            "question": p.get("input"),
            "answer": p.get("processed") or p.get("raw"),
        })
    if t == "result":
        return _ev("detection.result.done", {})          # signal — client GETs the full response
    if t == "run_end":
        return _ev("detection.run.completed", {})        # the ONE terminal event
    if t == "final":
        # A real finished trace holds BOTH `final` (from rlm-kit's record_main_trajectory) and `run_end`
        # (from the recorder's __exit__). Mapping BOTH to the terminal event would emit
        # `detection.run.completed` TWICE per replay — and the `final` copy lands BEFORE `result`, so a
        # client acting on the first `completed` fires before `detection.result.done`. `run_end` is the
        # canonical terminal; a truncated trace with `final` but no `run_end` (SIGKILL before __exit__)
        # is covered by the replay endpoint's synthesized-terminal fallback. So skip `final`.
        return None

    if t == "tool_call":
        tool = p.get("tool")
        args = p.get("args") or {}
        if tool == "scan_indicators":
            hits = p.get("hits") or []
            return _ev("detection.scan", {
                "region": args.get("region"),
                "n": p.get("n") if p.get("n") is not None else len(hits),
                "worst": _worst_severity(hits),
            })
        if tool == "deep_classify":
            # Three shapes normalized to one event. endpoint-error carries only `error` (no `ok` key),
            # so `ok` defaults to False there; circuit-break carries circuit_broken=True.
            return _ev("detection.classify", {
                "ok": bool(p.get("ok")),
                "circuit_broken": bool(p.get("circuit_broken", False)),
                "verdict": p.get("verdict"),
                "confidence": p.get("confidence"),
                "error": p.get("error"),                  # endpoint error, when present
                "errors": p.get("errors") or [],          # validation errors, when present
            })
        if tool == "fetch_url":
            return _ev("detection.fetch", {
                "url": args.get("url"), "ok": p.get("ok"),
                "status": p.get("status"), "bytes": p.get("bytes"),
                "note": p.get("note"),                    # the real outcome: ok / refused / error: …
            })
        if tool in ("read_skill", "list_skills"):
            return _ev("detection.skill.read", {"name": args.get("name") or "(catalog)"})

    return None  # unknown type / unsurfaced tool — skip


def _ev(name: str, data: dict) -> dict[str, Any]:
    return {"event": name, "data": data}
