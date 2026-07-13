"""Assemble the canonical verdict from the trace — the read-time step that makes the EVIDENCE a fact.

`assemble_verdict(verdict, events)` attaches the deterministic fields the SYSTEM owns to the planner's
JUDGEMENT (`ChangeVerdict`, no hits): the UNION of ALL indicator hits from the trace (baseline ∪ every
`scan_indicators` tool call — MF3), the derived max severity, whether to SIGNAL, and any indicator ids
the planner cited that match no recorded hit (a fabrication tell).

The `signal` decision is DETERMINISTIC and partly independent of the planner: it fires if the planner's
verdict is in `emit_on` OR a high/critical deterministic indicator fired. So a false-benign self-report
cannot suppress hard evidence from reaching the SIEM — the planner can skew the verdict, never hide the
indicators. (This is deterministic reduction over facts, NOT a model judgement smuggled into the read
path — the verdict tier stays the planner's; only the evidence-driven floor is ours.)

This runs everywhere the result is consumed — the live path (cli), re-render, and rl_export — so labels
read facts too. Old traces heal: pydantic ignores legacy keys; hits re-source from the trace.

Pure stdlib + pydantic; no dspy.
"""

from __future__ import annotations

from typing import Optional

from rlm_kit.trace import EVENT_RESULT, EVENT_RUN_START

from .indicators import hits_from_events
from .schema import (
    SIGNAL_SEVERITY_FLOOR,
    AssembledVerdict,
    ChangeVerdict,
    max_severity,
    severity_rank,
)

_DEFAULT_EMIT_ON = ("suspicious", "malicious")


def _emit_on_from_meta(events: list[dict]) -> tuple[str, ...]:
    """The `emit_on` the run actually used, recorded in run_start meta (so an OFFLINE re-render/export
    re-derives the SAME `signal` the live run emitted). Falls back to the default for an old trace."""
    for e in events:
        if e.get("type") == EVENT_RUN_START:
            eo = ((e.get("payload") or {}).get("meta") or {}).get("emit_on")
            if isinstance(eo, (list, tuple)) and eo:
                return tuple(eo)
    return _DEFAULT_EMIT_ON


def assemble_verdict(
    verdict: ChangeVerdict, events: list[dict], *, emit_on: tuple[str, ...] = _DEFAULT_EMIT_ON
) -> AssembledVerdict:
    """Attach the deterministic evidence + derived signal to the planner's judgement."""
    hits = hits_from_events(events)
    known_ids = {h.id for h in hits}
    cited_unknown = [cid for cid in (verdict.indicator_ids or []) if cid not in known_ids]
    top_sev = max_severity([h.severity for h in hits])

    verdict_signals = (verdict.verdict or "").strip().lower() in {v.lower() for v in emit_on}
    evidence_signals = severity_rank(top_sev) >= severity_rank(SIGNAL_SEVERITY_FLOOR)
    signal = bool(verdict_signals or evidence_signals)

    return AssembledVerdict(
        verdict=verdict.verdict,
        confidence=verdict.confidence,
        summary=verdict.summary,
        rationale=verdict.rationale,
        techniques=list(verdict.techniques or []),
        suspect_files=list(verdict.suspect_files or []),
        recommended_action=verdict.recommended_action,
        indicators=hits,
        max_indicator_severity=top_sev,
        signal=signal,
        cited_unknown_ids=cited_unknown,
    )


def verdict_from_events(events: list[dict], *, emit_on: Optional[tuple[str, ...]] = None
                        ) -> Optional[AssembledVerdict]:
    """Reconstruct the assembled verdict from a saved trace's result event, or None if the run produced
    no result (never finalized). `emit_on` defaults to the value recorded in the run's meta, so an
    offline re-render/export re-derives the SAME `signal` the live run emitted (finding 5)."""
    results = [e for e in events if e["type"] == EVENT_RESULT]
    if not results:
        return None
    out = results[-1]["payload"].get("output")
    if not isinstance(out, dict):
        return None
    resolved = emit_on if emit_on is not None else _emit_on_from_meta(events)
    return assemble_verdict(ChangeVerdict.from_payload(out), events, emit_on=resolved)
