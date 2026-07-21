"""Build the API-shaped `DetectionResponse` from an assembled verdict + the trace — a read-time
presentation carrying no new judgement. `build_failed_response` is the crash/cancel path (no verdict →
an informative refusal that still carries whatever deterministic indicators were gathered).

Pure stdlib + pydantic; no dspy.
"""

from __future__ import annotations

from typing import Optional

from rlm_kit.trace import EVENT_RUN_START

from .indicators import hits_from_events
from .normalize import has_groundable_content
from .rubric import criteria_facts, default_rubric, rubric_from_meta
from .schema import (
    INCONCLUSIVE_VERDICT,
    AssembledVerdict,
    DetectionResponse,
    ProcessInfo,
    RefusalInfo,
    RubricCriterionView,
    RubricReport,
)


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


def _rubric(events: list[dict]) -> RubricReport:
    """The run's ATLAS TF/TA/TG/PA rubric as a reward-free presentation: join each deterministic
    `CriterionFact` (from `criteria_facts`) with its skeleton `description`. Pure serialization — adds NO
    judgement and NO score (mirrors `rl_export.rubric_signal`). Works on a partial/empty trace too, so it
    is attached on every status (a failed run still has a trajectory worth labelling)."""
    skel = {c.name: c for c in (rubric_from_meta(events).criteria or default_rubric().criteria)}
    criteria = [
        RubricCriterionView(
            criterion=f.criterion,
            category=f.category,
            description=(skel[f.criterion].description if f.criterion in skel else ""),
            weight=f.weight,
            observed=f.observed,
        )
        for f in criteria_facts(events)
    ]
    return RubricReport(criteria=criteria)


def _has_groundable_content(events: list[dict]) -> bool:
    """Whether the run's normalized change carried real untrusted content — read from the `event` string
    in run_start meta. Absent/unparseable → True, so a normal run is never mis-downgraded."""
    ev = _meta(events).get("event")
    return has_groundable_content(ev) if isinstance(ev, str) else True


def _resolve_outcome(assembled: AssembledVerdict, events: list[dict]) -> tuple[str, str, str]:
    """The response status for a FINALIZED run + the refusal (reason, detail) when it is not `classified`.
    A finalized run is `classified` UNLESS the planner submitted no verdict (legacy empty), submitted the
    sanctioned `inconclusive` outcome, OR the normalized change carried NO groundable content — in which
    case a confident verdict is DOWNGRADED to inconclusive (defense-in-depth: an ungroundable input must
    never ship a confident verdict)."""
    verdict = (assembled.verdict or "").strip().lower()
    if not verdict:
        return "inconclusive", "inconclusive", "The run finalized without a usable verdict."
    if verdict == INCONCLUSIVE_VERDICT:
        return ("inconclusive", "insufficient_evidence",
                "The classifier judged the change not assessable — insufficient evidence to ground a verdict.")
    if not _has_groundable_content(events):
        return ("inconclusive", "insufficient_evidence",
                "The change carried no groundable content to assess; no confident verdict was warranted.")
    return "classified", "", ""


def build_response(assembled: AssembledVerdict, events: list[dict], run_id: str) -> DetectionResponse:
    """Serialize a completed run as a `DetectionResponse`."""
    status, reason, detail = _resolve_outcome(assembled, events)
    ts = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    created = int(min(ts)) if ts else 0
    common = dict(
        id=run_id, created=created, model=_models(events), source=_source(events),
        process=_process(events),
        rubric=_rubric(events),   # ATLAS TF/TA/TG/PA reward-free labels (surfaced, not judged)
    )
    if status != "classified":
        return DetectionResponse(
            status="inconclusive",
            refusal=RefusalInfo(reason=reason, detail=detail, indicators=assembled.indicators),
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
        rubric=_rubric(events),   # a failed/cancelled run still has a partial trajectory worth labelling
    )
