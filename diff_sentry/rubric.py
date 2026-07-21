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
dspy-free at module top (imports only `.schema` + `rlm_kit.rubric`, both dspy-free) — the rl_export reuse
is a function-level import, and its call path (rl_export → assemble → indicators) is itself dspy-free.
"""

from __future__ import annotations

from typing import Optional

from rlm_kit.rubric import (  # the reward-free rubric PRIMITIVES (category-agnostic); wrapped below
    Criterion,
    CriterionFact,
    RubricCriteria,
    criteria_facts as _kit_criteria_facts,
    rubric_from_meta as _kit_rubric_from_meta,
    rubric_to_meta,  # noqa: F401 — re-exported (cli/rl_export do `from .rubric import rubric_to_meta`)
    validate_rubric as _kit_validate_rubric,
)

from .schema import CRITERION_CATEGORIES

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


def rubric_from_meta(events: list[dict]) -> RubricCriteria:
    """Recover the rubric stored in a run's run_start meta (empty if none), filtered to diff-sentry's
    ATLAS categories. Thin wrapper over rlm-kit's taxonomy-agnostic primitive."""
    return _kit_rubric_from_meta(events, categories=CRITERION_CATEGORIES)


def trace_facts(events: list[dict]) -> dict:
    """The deterministic evidence surface for one run — the raw material every category lens slices.

    REUSES the project's OWN canonical facts: `rl_export.run_labels` (verdict / signal / indicator_count /
    max_indicator_severity / cited_unknown) + `run_metrics` (steps, scan / deep_classify / analyst / fetch
    counts, circuit-breaks, cap). Their key-sets are DISJOINT, so the merge drops nothing; sourcing them
    here rather than re-deriving keeps `criteria_facts` provably consistent with the export's labels/metrics
    (no second facts derivation to drift). The import is LAZY so this module's top stays dspy-free (it
    imports only `.schema` + the dspy-free `rlm_kit.rubric`) — the rl_export call path
    (→ assemble.verdict_from_events → indicators) is itself dspy-free."""
    from .rl_export import run_labels, run_metrics  # lazy: keeps rubric's module top dspy-free

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
    """A DETERMINISTIC structural lint of a rubric (NOT a semantic-quality judge) — diff-sentry's ATLAS
    category coverage + the observability heuristic. Thin wrapper over rlm-kit's primitive."""
    return _kit_validate_rubric(rubric, categories=CRITERION_CATEGORIES, observable_vocab=_OBSERVABLE_VOCAB)


def criteria_facts(events: list[dict], criteria: Optional[list[Criterion]] = None) -> list[CriterionFact]:
    """Per-criterion DETERMINISTIC facts from the trace. `criteria` defaults to the run's recorded rubric,
    falling back to `default_rubric()` when a trace carries none — SAFE because the skeleton is constant.

    Sources the facts from diff-sentry's OWN `trace_facts` and slices them through `_CATEGORY_LENS` via
    rlm-kit's pure `criteria_facts` primitive. NEVER decides met/unmet or a score."""
    if criteria is None:
        criteria = rubric_from_meta(events).criteria or default_rubric().criteria
    return _kit_criteria_facts(criteria, trace_facts(events), _CATEGORY_LENS)
