"""Build the API-shaped `DetectionResponse` from an assembled verdict + the trace — a read-time
presentation carrying no new judgement. `build_failed_response` is the crash/cancel path (no verdict →
an informative refusal that still carries whatever deterministic indicators were gathered).

Pure stdlib + pydantic; no dspy.
"""

from __future__ import annotations

from typing import Optional

from rlm_kit.trace import EVENT_RUN_START

from .indicators import hits_from_events
from .schema import AssembledVerdict, DetectionResponse, ProcessInfo, RefusalInfo


def _meta(events: list[dict]) -> dict:
    for e in events:
        if e.get("type") == EVENT_RUN_START:
            return (e.get("payload") or {}).get("meta") or {}
    return {}


def _source(events: list[dict]) -> Optional[dict]:
    src = _meta(events).get("source")
    return src if isinstance(src, dict) else None


def _models(events: list[dict]) -> dict:
    m = _meta(events)
    return {k: m.get(k) for k in ("planner", "analyst", "classifier") if m.get(k)}


def _elapsed_s(events: list[dict]) -> Optional[float]:
    ts = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    return round(max(ts) - min(ts), 3) if len(ts) >= 2 else None


def _process(events: list[dict]) -> ProcessInfo:
    def _tool(name: str) -> int:
        return sum(1 for e in events
                   if e["type"] == "tool_call" and e["payload"].get("tool") == name)

    steps = sum(1 for e in events if e["type"] == "main_step")
    cap = _meta(events).get("max_iterations")
    return ProcessInfo(
        steps=steps,
        scan_calls=_tool("scan_indicators"),
        deep_classify_calls=sum(
            1 for e in events if e["type"] == "tool_call"
            and e["payload"].get("tool") == "deep_classify" and not e["payload"].get("circuit_broken")),
        deep_classify_circuit_breaks=sum(
            1 for e in events if e["type"] == "tool_call"
            and e["payload"].get("tool") == "deep_classify" and e["payload"].get("circuit_broken")),
        analyst_calls=sum(1 for e in events if e["type"] == "sub_call"),
        fetches=_tool("fetch_url"),
        elapsed_s=_elapsed_s(events),
        hit_iteration_cap=bool(isinstance(cap, int) and cap > 0 and steps >= cap),
    )


def _status(assembled: AssembledVerdict) -> str:
    return "classified" if (assembled.verdict or "").strip() else "inconclusive"


def build_response(assembled: AssembledVerdict, events: list[dict], run_id: str) -> DetectionResponse:
    """Serialize a completed run as a `DetectionResponse`."""
    status = _status(assembled)
    ts = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    created = int(min(ts)) if ts else 0
    common = dict(
        id=run_id, created=created, model=_models(events), source=_source(events),
        process=_process(events),
    )
    if status != "classified":
        return DetectionResponse(
            status="inconclusive",
            refusal=RefusalInfo(reason="inconclusive", detail="The run finalized without a usable verdict.",
                                indicators=assembled.indicators),
            indicators=assembled.indicators, max_indicator_severity=assembled.max_indicator_severity,
            signal=assembled.signal, **common,
        )
    return DetectionResponse(
        status="classified",
        verdict=assembled.verdict,
        confidence=assembled.confidence,
        signal=assembled.signal,
        summary=assembled.summary,
        rationale=assembled.rationale,
        techniques=assembled.techniques,
        suspect_files=assembled.suspect_files,
        recommended_action=assembled.recommended_action,
        indicators=assembled.indicators,
        max_indicator_severity=assembled.max_indicator_severity,
        **common,
    )


def build_failed_response(run_id: str, events: list[dict], detail: str, *, reason: str = "run_failed"
                          ) -> DetectionResponse:
    """The crash/cancel path — no verdict, but still carries the deterministic indicators gathered and
    the derived signal (a run that crashed AFTER a critical indicator fired must STILL be able to alert)."""
    from .schema import SIGNAL_SEVERITY_FLOOR, max_severity, severity_rank

    hits = hits_from_events(events)
    top = max_severity([h.severity for h in hits])
    signal = severity_rank(top) >= severity_rank(SIGNAL_SEVERITY_FLOOR)
    return DetectionResponse(
        id=run_id, status="failed", model=_models(events), source=_source(events),
        signal=signal, indicators=hits, max_indicator_severity=top,
        refusal=RefusalInfo(reason=reason, detail=detail, indicators=hits),
        process=_process(events),
    )
