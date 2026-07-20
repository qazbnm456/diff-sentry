"""Rubrics — the ATLAS decomposition of "did this run succeed?" into observable CRITERIA.

diff-sentry's task is CONSTANT ("classify ONE GitHub change for malicious intent"), so — unlike a harness
whose tasks vary and are decomposed per-task by a frontier model — the rubric here is a FIXED, deterministic
skeleton: `default_rubric()` returns the SAME four criteria (one per ATLAS category) every run. There is NO
LLM path (no generate_rubric / parse_rubric): only the FACTS vary per run, not the criteria. Two
deterministic, dspy-free halves:

1. STRUCTURE. `default_rubric()` — the fixed skeleton, one `Criterion` per category (TF/TA/TG/PA), carried
   in a run's run_start meta as LABELS (category + weight, never a score). `rubric_to_meta` /
   `rubric_from_meta` serialize it there.

2. READ-TIME FACTS. `criteria_facts(events, criteria)` re-sources, per criterion, the DETERMINISTIC
   evidence its category cares about — a FACT surface, never a judgement. The facts come from the project's
   OWN canonical source of truth (`rl_export.run_labels` + `run_metrics`, reused via a LAZY import), so a
   criterion's `observed` dict can never drift from the `labels`/`metrics` a trainer reads from the same
   export bundle. `met`/`unmet`/reward is the trainer's (or a downstream judge's) call — never computed here.

This holds ATLAS (a TRAINING/RFT paper) inside rlm-kit's "trajectories, never reward" invariant: emit the
rubric + per-criterion facts as data; scoring stays downstream. The rubric is a trainer/eval-side artifact
the planner NEVER sees at inference (it lives only in run_start meta, not in INSTRUCTIONS or any tool).
dspy-free at module top (imports only `.schema` + stdlib) — the rl_export reuse is a function-level import,
and its call path (rl_export → assemble → indicators) is itself dspy-free.
"""

from __future__ import annotations

from typing import Optional

from .schema import CRITERION_CATEGORIES, Criterion, CriterionFact, RubricCriteria

# The human-readable meaning of each ATLAS category — a documentation glossary (kept in sync with
# CRITERION_CATEGORIES by a test). The machinery reads the per-criterion `description`s in default_rubric()
# and the fact keys in _CATEGORY_LENS; this table is for readers, not consumed by either.
CATEGORY_MEANING = {
    "TF": "Task Fulfillment — the run produced a decisive verdict that resolves the change-analysis task.",
    "TA": "Tool Appropriateness — scan / deep_classify / analyst / fetch tools were used to converge, not thrash.",
    "TG": "Tool Grounding — the verdict rests on the deterministic indicator evidence actually recorded, not invented.",
    "PA": "Parameter Accuracy — the submitted classification is well-formed (a valid verdict, no fabricated citations).",
}


def default_rubric(task: str = "") -> RubricCriteria:
    """The FIXED, deterministic rubric skeleton — one criterion per ATLAS category, weight 1.0, NO model.

    `task` is accepted for signature parity (and future extensibility) but unused: the criteria are
    CONSTANT because diff-sentry's task never varies — only the per-run FACTS do."""
    return RubricCriteria(criteria=[
        Criterion(name="verdict_resolves_change", category="TF", weight=1.0,
                  description="The run finalized a decisive benign/suspicious/malicious verdict for the "
                              "change — resolving the change-analysis task — without being cut off at the "
                              "iteration budget."),
        Criterion(name="tools_used_appropriately", category="TA", weight=1.0,
                  description="The scan_indicators sweep, the deep_classify second stage, analyst "
                              "escalations, and reference fetches drove convergence — bounded deep_classify "
                              "calls and circuit-breaks, escalating when warranted rather than thrashing."),
        Criterion(name="verdict_grounded_in_indicators", category="TG", weight=1.0,
                  description="The verdict rests on the deterministic indicator evidence actually recorded "
                              "(the derived signal and max severity), not invented — no cited indicator ids "
                              "that match no recorded hit."),
        Criterion(name="classification_wellformed", category="PA", weight=1.0,
                  description="The submitted classification is well-formed — a valid verdict label and no "
                              "fabricated indicator citations (cited ids matching no recorded hit)."),
    ])


def rubric_to_meta(rubric: RubricCriteria) -> list[dict]:
    """Serialize the rubric for run_start meta (LABELS carried alongside the run — never a reward)."""
    return [c.model_dump() for c in rubric.criteria]


def rubric_from_meta(events: list[dict]) -> RubricCriteria:
    """Recover the rubric stored in a run's run_start meta (empty if none was recorded)."""
    for e in events:
        if e.get("type") == "run_start":
            raw = ((e.get("payload") or {}).get("meta") or {}).get("rubric")
            if isinstance(raw, list):
                crits: list[Criterion] = []
                for c in raw:
                    if not isinstance(c, dict) or c.get("category") not in CRITERION_CATEGORIES:
                        continue
                    try:  # skip a malformed entry (missing name/description) — never crash the read path
                        crits.append(Criterion(**c))
                    except (TypeError, ValueError):
                        continue
                return RubricCriteria(criteria=crits)
    return RubricCriteria(criteria=[])


def trace_facts(events: list[dict]) -> dict:
    """The deterministic evidence surface for one run — the raw material every category lens slices.

    REUSES the project's OWN canonical facts: `rl_export.run_labels` (verdict / signal / indicator_count /
    max_indicator_severity / cited_unknown) + `run_metrics` (steps, scan / deep_classify / analyst / fetch
    counts, circuit-breaks, cap). Their key-sets are DISJOINT, so the merge drops nothing; sourcing them
    here rather than re-deriving keeps `criteria_facts` provably consistent with the export's labels/metrics
    (no second facts derivation to drift). The import is LAZY so this module's top stays dspy-free /
    rlm-kit-free — the rl_export call path (→ assemble.verdict_from_events → indicators) is itself
    dspy-free."""
    from .rl_export import run_labels, run_metrics  # lazy: keeps rubric's module top dspy/rlm-kit-free

    return {**run_labels(events), **run_metrics(events)}


# Which raw facts each category's CriterionFact surfaces — a VIEW over `trace_facts`, NOT a partition:
# `verdict` (TF+PA), `signal` (TF+TG) and `cited_unknown` (TG+PA) deliberately appear in two lenses each,
# each a distinct signal (fulfillment vs well-formedness; decisiveness vs grounding; fabrication tell).
_CATEGORY_LENS = {
    "TF": ("verdict", "signal", "hit_iteration_cap"),
    "TA": ("scan_calls", "deep_classify_calls", "deep_classify_circuit_breaks", "analyst_calls",
           "fetches", "skill_reads"),
    "TG": ("indicator_count", "max_indicator_severity", "signal", "cited_unknown"),
    "PA": ("verdict", "cited_unknown"),
}

# Vocabulary a criterion description should touch to be plausibly OBSERVABLE from a trace (ATLAS: criteria
# must be observable, not surface-quality). diff-sentry domain terms — a deterministic heuristic, NOT a judge.
_OBSERVABLE_VOCAB = ("verdict", "change", "classify", "classification", "benign", "suspicious", "malicious",
                     "indicator", "evidence", "signal", "severity", "scan", "deep_classify", "analyst",
                     "escalat", "fetch", "skill", "tool", "call", "cited", "fabricat", "ground", "iteration",
                     "decisive", "resolve", "circuit")


def validate_rubric(rubric: RubricCriteria) -> list[str]:
    """A DETERMINISTIC structural lint of a rubric (NOT a semantic-quality judge). Returns human-readable
    issues (empty list = clean): all four categories represented, unique names, non-empty descriptions, and
    a weak trace-observability heuristic. Deeper "is this rubric GOOD" validation needs a real training
    signal — out of scope here."""
    criteria = rubric.criteria
    if not criteria:
        return ["rubric has no criteria"]
    issues: list[str] = []
    present = {c.category for c in criteria}
    missing = [cat for cat in CRITERION_CATEGORIES if cat not in present]
    if missing:
        issues.append(f"categories not represented: {missing}")
    names = [c.name for c in criteria]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        issues.append(f"duplicate criterion names: {dupes}")
    empty = [c.name for c in criteria if not (c.description or "").strip()]
    if empty:
        issues.append(f"criteria with empty descriptions: {empty}")
    vague = [c.name for c in criteria
             if not any(w in (c.description or "").lower() for w in _OBSERVABLE_VOCAB)]
    if vague:
        issues.append("criteria whose description may not be trace-observable (mentions no "
                      f"verdict/indicator/signal/classify/...): {vague}")
    return issues


def criteria_facts(events: list[dict], criteria: Optional[list[Criterion]] = None) -> list[CriterionFact]:
    """Per-criterion DETERMINISTIC facts from the trace. `criteria` defaults to the run's recorded rubric,
    falling back to `default_rubric()` when a trace carries none (legacy traces, or a run whose CLI meta
    wasn't written) — SAFE because the skeleton is constant, so every trace yields full per-category facts.

    Each `CriterionFact.observed` holds the raw facts its category cares about — a FACT surface for the
    trainer (or a downstream judge) to score against. This function NEVER decides met/unmet or a score."""
    if criteria is None:
        criteria = rubric_from_meta(events).criteria or default_rubric().criteria
    facts = trace_facts(events)
    out: list[CriterionFact] = []
    for c in criteria:
        lens = _CATEGORY_LENS.get(c.category, ())
        observed = {k: facts[k] for k in lens if k in facts}
        out.append(CriterionFact(criterion=c.name, category=c.category, weight=c.weight, observed=observed))
    return out
