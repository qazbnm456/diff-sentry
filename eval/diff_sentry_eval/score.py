"""Score one recorded diff-sentry run against its EvalTask, then aggregate rows into the scorecard.

The READ side of the harness: it reconstructs the ATLAS judge's inputs DETERMINISTICALLY from the existing
trace contract, reaching diff-sentry ONLY through its PUBLIC surface (the same rule the studio follows) —
never a private internal:

- `diff_sentry.verdict_from_events` → the assembled `AssembledVerdict` (the planner's judgement UNIONed
  with the deterministic indicator evidence + the DERIVED signal — so the judge grades the real artifact
  the system emits, not the planner's raw self-report);
- `diff_sentry.run_labels` (verdict / signal / indicator_count / max_indicator_severity / cited_unknown) ∪
  `diff_sentry.run_metrics` (scan / deep_classify / analyst / fetch counts, cap) for the execution summary
  + the deterministic cross-check facts.

NO new trace field is read or written. The planner-visible CHANGE for the judge comes from the run's
`run_start` meta (the exact normalized untrusted content), falling back to the EvalTask's change payload.
`aggregate` computes per-category MEANS (TF primary), never a weighted composite or a pass/fail.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from statistics import fmean

from diff_sentry import AssembledVerdict, run_labels, run_metrics, verdict_from_events

from .judge import JudgeVerdict
from .schema import CATEGORIES, EvalReport, EvalRow
from .taskset import EvalTask

_METRIC_KEYS = ("steps", "scan_calls", "deep_classify_calls", "deep_classify_circuit_breaks",
                "analyst_calls", "analyst_failures", "fetches", "skill_reads", "hit_iteration_cap")


def _run_id(events: list[dict]) -> str:
    for event in events:
        rid = event.get("run_id")
        if rid:
            return str(rid)
    return ""


def _trace_facts(events: list[dict]) -> dict:
    """run_labels ∪ run_metrics — the deterministic facts every category lens slices. Their key-sets are
    DISJOINT, so the merge drops nothing (mirrors `diff_sentry.rubric.trace_facts`, kept on the public
    surface)."""
    return {**run_labels(events), **run_metrics(events)}


def _assembled(events: list[dict]) -> AssembledVerdict | None:
    """The assembled verdict, or None if the run never finalized (no result event, or a result whose
    output is not an object). The caller turns None into an `unscored` row."""
    return verdict_from_events(events)


def _change_from_meta(events: list[dict]) -> str:
    """The exact normalized untrusted content the planner saw, echoed in run_start meta (`event`)."""
    for event in events:
        if event.get("type") == "run_start":
            return str(((event.get("payload") or {}).get("meta") or {}).get("event", ""))
    return ""


def _change_for_judge(events: list[dict], eval_task: EvalTask) -> str:
    """Prefer the run's OWN normalized change (what the planner actually classified); fall back to a JSON
    dump of the task's change payload for a trace that carried no `event` meta."""
    change = _change_from_meta(events)
    if change.strip():
        return change
    return json.dumps(eval_task.change, ensure_ascii=False, indent=2) if eval_task.change else ""


def _verdict_block(a: AssembledVerdict) -> str:
    """The compact classification the judge grades — the assembled verdict + the planner's reasoning."""
    techniques = ", ".join(a.techniques) or "(none)"
    suspects = ", ".join(a.suspect_files) or "(none)"
    return "\n".join([
        (f"Verdict: {a.verdict} (confidence {a.confidence}) · recommended action: "
         f"{a.recommended_action} · SIEM signal: {a.signal}"),
        f"Summary: {a.summary}",
        f"Rationale: {a.rationale}",
        f"Techniques: {techniques}",
        f"Suspect files: {suspects}",
    ])


def _indicators_block(a: AssembledVerdict, *, limit: int = 20) -> str:
    """The deterministic indicator evidence union, bounded — the FACTS a signal is built on (never the
    planner's self-report). `cited_unknown_ids` are surfaced as the fabrication tell for the judge's TG/PA."""
    hits = a.indicators[:limit]
    if not hits:
        lines = ["(no deterministic indicators fired)"]
    else:
        lines = [f"- [{h.severity}] {h.rule} — {h.title}"
                 + (f" (decoded → {h.decoded})" if h.decoded else "")
                 + (f" @ {h.location}" if h.location else "")
                 for h in hits]
        if len(a.indicators) > limit:
            lines.append(f"… (+{len(a.indicators) - limit} more)")
    if a.cited_unknown_ids:
        lines.append(f"FABRICATED CITATIONS (cited ids matching no recorded hit): {a.cited_unknown_ids}")
    return "\n".join(lines)


def _execution_summary(events: list[dict]) -> str:
    """The deterministic narrative the judge reads — the derived verdict/signal/evidence + the effort
    counters, all re-sourced from run_labels ∪ run_metrics, never the planner's self-report."""
    f = _trace_facts(events)
    refused = f.get("analyst_failures")
    return "\n".join([
        f"assembled verdict: {f.get('verdict')} · derived SIEM signal: {f.get('signal')}",
        (f"deterministic indicators: {f.get('indicator_count', 0)} (max severity "
         f"{f.get('max_indicator_severity', 'info')}); cited-but-unrecorded: {f.get('cited_unknown', 0)}"),
        (f"tools: {f.get('scan_calls', 0)} scan(s), {f.get('deep_classify_calls', 0)} deep-classify "
         f"({f.get('deep_classify_circuit_breaks', 0)} circuit-broken), {f.get('analyst_calls', 0)} "
         f"analyst escalation(s){f' ({refused} refused by the provider)' if refused else ''}, "
         f"{f.get('fetches', 0)} fetch(es), {f.get('skill_reads', 0)} skill read(s)"),
    ])


def build_judge_inputs(events: list[dict], eval_task: EvalTask,
                       assembled: AssembledVerdict | None = None) -> dict | None:
    """Reconstruct the ATLAS judge's inputs from the trace, or None for a run with no usable verdict.

    `assembled` may be passed when the caller already built it (`score_run` does); otherwise it is
    re-derived here. A finalized run with an EMPTY verdict label is treated the same as no result: there
    is no classification to judge → None. (The sanctioned `inconclusive` label is a classification and is
    judged like any other.) The `change` is the run's normalized content, falling back
    to the task's change payload."""
    assembled = assembled if assembled is not None else _assembled(events)
    if assembled is None or not (assembled.verdict or "").strip():
        return None
    f = _trace_facts(events)
    return {
        "change": _change_for_judge(events, eval_task),
        "reference": eval_task.reference or "(no reference provided; grade against the change itself)",
        "verdict": _verdict_block(assembled),
        "indicators": _indicators_block(assembled),
        "execution_summary": _execution_summary(events),
        "total_rounds": int(f.get("steps", 0)),
    }


def score_run(events: list[dict], eval_task: EvalTask,
              judge: Callable[[dict], JudgeVerdict]) -> EvalRow:
    """One run → one EvalRow: judge inputs from the trace, the judge's verdict, plus the deterministic
    facts (metrics + verdict/signal/severity/cited_unknown) surfaced side by side as a cross-check. Never
    raises on a bad run: never-finalized, finalized with an empty verdict label, and judge-failed each
    become an `unscored` row with the reason, never a fake 0."""
    run_id = _run_id(events) or eval_task.id
    assembled = _assembled(events)
    if assembled is None:
        return EvalRow(task_id=eval_task.id, run_id=run_id, unscored=True,
                       unscored_reason="run never finalized (no result event in the trace)")
    facts = _trace_facts(events)
    metrics = {k: facts[k] for k in _METRIC_KEYS if k in facts}
    verdict = str(assembled.verdict or "")
    signal = bool(assembled.signal)
    top = str(assembled.max_indicator_severity or "info")
    cited_unknown = len(assembled.cited_unknown_ids)
    if not verdict.strip():
        return EvalRow(task_id=eval_task.id, run_id=run_id, metrics=metrics, verdict="", signal=signal,
                       max_indicator_severity=top, cited_unknown=cited_unknown, unscored=True,
                       unscored_reason="run finalized without a usable verdict")
    result = judge(build_judge_inputs(events, eval_task, assembled))
    if not result.ok or result.score is None:
        return EvalRow(task_id=eval_task.id, run_id=run_id, metrics=metrics, verdict=verdict, signal=signal,
                       max_indicator_severity=top, cited_unknown=cited_unknown, unscored=True,
                       unscored_reason=result.reason or "judge returned no score")
    return EvalRow(task_id=eval_task.id, run_id=run_id, score=result.score, metrics=metrics,
                   verdict=verdict, signal=signal, max_indicator_severity=top, cited_unknown=cited_unknown)


def aggregate(rows: list[EvalRow], *, taskset: str, judge_model: str = "",
              prompt_version: str = "") -> EvalReport:
    """Rows → the scorecard: per-category ARITHMETIC MEANS over the scored rows, TF primary.

    Unscored rows count in `n`/`n_unscored` but never enter the means (unscored is not 0). There is no
    composite and no threshold here by design — the report is a measurement, not a signal.
    """
    scored = [r for r in rows if not r.unscored and r.score is not None]
    means: dict[str, float] = {}
    if scored:
        for cat in CATEGORIES:
            means[cat] = round(fmean(getattr(r.score, cat) for r in scored), 2)
    return EvalReport(taskset=taskset, n=len(rows), n_unscored=len(rows) - len(scored),
                      judge_model=judge_model, prompt_version=prompt_version,
                      means=means, rows=list(rows))
