"""diff-sentry-eval's OWN report shapes — deliberately NOT in (or imported from) `diff_sentry.schema`.

The separation is the reward fence: `diff_sentry.schema` stays score-free, and the eval score lives HERE,
in a package the rollout core never imports. Structurally there is NO composite score and NO reward field
anywhere in these models: `EvalScore` is four independent 0-10 category measurements, `EvalReport`'s
aggregate is per-category MEANS (TF flagged primary, matching ATLAS), never a weighted sum. Composing a
single number out of these is a downstream operator's call — doing it here would turn a measurement into a
training signal.

Pure pydantic; no dspy, no openai, no diff_sentry import.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

# The four ATLAS judge categories, change-analysis domain: Classification Fulfillment (the primary metric),
# Approach Appropriateness, Evidence Grounding, Classification Accuracy. Same category CODES as the rollout
# rubric (comparability), different MEANINGS (they measure different objects — see the README table).
CATEGORIES = ("TF", "TA", "TG", "PA")


class EvalScore(BaseModel):
    """One external-judge verdict: four INDEPENDENT 0-10 category scores + optional notes.

    There is intentionally no total/composite field — the categories are reported side by side.
    """

    TF: float = Field(..., ge=0.0, le=10.0, description="Classification Fulfillment (0-10) — the primary metric")
    TA: float = Field(..., ge=0.0, le=10.0, description="Approach Appropriateness (0-10)")
    TG: float = Field(..., ge=0.0, le=10.0, description="Evidence Grounding (0-10)")
    PA: float = Field(..., ge=0.0, le=10.0, description="Classification Accuracy (0-10)")
    notes: str = Field("", description="the judge's short free-text rationale (diagnostic, not a score)")


class EvalRow(BaseModel):
    """One scored run: the judge's category scores + deterministic trace-derived facts, side by side.

    `metrics` (run_metrics) + `verdict`/`signal`/`max_indicator_severity`/`cited_unknown` are objective
    observations surfaced as a cheap cross-check on the judge (a high TG next to `cited_unknown>0`, or a
    high TF next to an empty verdict, is suspect) — facts, never a reward. A run that never finalized,
    produced no usable verdict, or that the judge could not score is `unscored` with the reason — never a
    fake 0, which would lie in the aggregate.
    """

    task_id: str
    run_id: str
    score: Optional[EvalScore] = None
    metrics: dict = Field(default_factory=dict, description="run_metrics (steps, scan/deep_classify/analyst calls…)")
    verdict: str = Field("", description="the assembled verdict (benign/suspicious/malicious/none) — a fact")
    signal: bool = Field(False, description="the deterministically DERIVED SIEM signal — a fact, not the judge's")
    max_indicator_severity: str = Field("info", description="highest deterministic indicator severity — a fact")
    cited_unknown: int = Field(0, description="count of cited indicator ids matching no recorded hit (fabrication tell)")
    unscored: bool = False
    unscored_reason: str = ""


class EvalReport(BaseModel):
    """The terminal scorecard for one taskset: per-task rows + per-category MEANS over the scored rows.

    `means` holds one arithmetic mean per category ({"TF": .., "TA": .., "TG": .., "PA": ..}); `primary`
    names TF as the headline metric (ATLAS: TF is primary, TA/TG/PA are diagnostics). The judge model +
    prompt version are pinned so a number is reproducible. No composite, no threshold, no pass/fail —
    this report is read, never trained on.
    """

    taskset: str
    n: int = Field(..., description="total runs considered (scored + unscored)")
    n_unscored: int = Field(0, description="runs excluded from the means (never finalized / no verdict / judge failed)")
    primary: str = "TF"
    judge_model: str = Field("", description="the judge actually used (a model id, or 'stub')")
    prompt_version: str = Field("", description="the eval prompt version the scores came from")
    means: dict[str, float] = Field(default_factory=dict, description="per-category means over scored rows")
    rows: list[EvalRow] = Field(default_factory=list)
