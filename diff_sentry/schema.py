"""Output models for diff-sentry (the RLMTask's validated output + the assembled result + the API shape).

The load-bearing convention (inherited from the rlm-kit consumers): the planner SUBMITs JUDGEMENT only.
The authoritative EVIDENCE — the deterministic indicator hits a signal is built on — is NEVER the
planner's to write. `scan_indicators` records its structured hits into the trace (and a host-side
BASELINE scan lands in the run_start meta), and the SYSTEM re-sources the FULL UNION of those hits on
read (`assemble.assemble_verdict`). The planner may only CITE hit ids (`indicator_ids`); it cannot
suppress evidence by omitting it, and it cannot invent it (a cited id with no matching hit is flagged).

Pure pydantic; no dspy — trivially unit-testable.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

# reward-free rubric TYPES — now rlm-kit's shared, taxonomy-agnostic primitives, re-exported here so
# diff-sentry's own `from .schema import Criterion, ...` call sites are unchanged.
from rlm_kit.rubric import Criterion, CriterionFact, RubricCriteria  # noqa: F401 (re-export, back-compat)

# ─── ATLAS rubric (a rollout LABEL surface, never a reward) ────────────────────────────────────
# The four ATLAS criterion categories: Task Fulfillment, Tool Appropriateness, Tool Grounding,
# Parameter Accuracy. The rubric TYPES above are rlm-kit's (category is opaque to the kit); diff-sentry
# owns only this ATLAS category set + the criterion descriptions + the lens (see rubric.py). The rubric is
# carried in run_start meta as LABELS; scoring (dᵢ∈[0,1]) is the downstream TRAINER's job, never here.
CRITERION_CATEGORIES = ("TF", "TA", "TG", "PA")


# The allowed verdict labels + the ranked severities, kept as plain data so deterministic code
# (assemble/response) can compare them without importing an enum machinery the model must satisfy.
VERDICTS = ("benign", "suspicious", "malicious")
SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# The deterministic severity floor: a hit AT OR ABOVE this forces a SIEM signal regardless of the
# planner's verdict, so a false-benign self-report can't suppress hard evidence (MF3). Shared by the
# live assemble path AND the crash/failed path so they can never diverge.
SIGNAL_SEVERITY_FLOOR = "high"


def severity_rank(sev: str) -> int:
    """Rank a severity string (unknown → -1, below `info`)."""
    return _SEV_RANK.get((sev or "").strip().lower(), -1)


def max_severity(sevs) -> str:
    """The highest severity in `sevs`, or "info" when empty/unknown — a deterministic reduction."""
    best, best_rank = "info", -1
    for s in sevs:
        r = severity_rank(s)
        if r > best_rank:
            best, best_rank = (s or "").strip().lower(), r
    return best if best_rank >= 0 else "info"


# ── the deterministic evidence layer (produced by indicators.scan_indicators, NEVER the planner) ──

class IndicatorHit(BaseModel):
    """One deterministic detector hit — a FACT the scanner recorded, not a model opinion.

    `id` is deterministic (a stable hash of rule + evidence, see indicators.mint_id) so the same hit
    minted host-side (baseline) and in a scan_indicators tool call de-duplicates to ONE union member,
    and the planner can cite it by a stable key.
    """

    id: str = Field(..., description="Deterministic hit id — `ind-<rule>-<hash8>`.")
    rule: str = Field(..., description="Detector rule name, e.g. `ci-shell-injection`, `curl-pipe-shell`.")
    severity: str = Field("medium", description="info | low | medium | high | critical.")
    title: str = Field(..., description="One-line human summary of what fired.")
    evidence: str = Field("", description="A BOUNDED snippet of the matched region (never the whole diff).")
    location: str = Field("", description="Where it fired — a filename, `filename:` prefix, or region label.")
    decoded: Optional[str] = Field(default=None, description="Decoded payload when the rule de-obfuscated one.")


# ── the planner's SUBMIT: JUDGEMENT only (the RLMTask output_model) ───────────────────────────────

class ChangeVerdict(BaseModel):
    """What the PLANNER submits — JUDGEMENT only. Carries NO raw diff bytes and NO indicator hits.

    `indicator_ids` are CITATIONS (which deterministic hits the planner leaned on), validated on read;
    they never gate which hits reach the signal — `assemble_verdict` unions ALL hits from the trace.
    """

    summary: str = Field(..., description="One or two sentences: what the change is and the call you made.")
    verdict: str = Field(
        ..., description="benign | suspicious | malicious — your classification of INTENT.")
    confidence: float = Field(
        0.5, ge=0.0, le=1.0, description="0..1 confidence in the verdict.")
    rationale: str = Field(
        ..., description="Why — grounded in the change and the indicator hits, not a vibe.")
    techniques: list[str] = Field(
        default_factory=list,
        description="Attack techniques observed, one short slug each: ci-shell-injection | "
        "obfuscated-payload | curl-pipe-shell | prompt-injection | data-exfiltration | codeowners-tamper "
        "| workflow-tamper | dependency-confusion | ... (empty for benign).",
    )
    suspect_files: list[str] = Field(
        default_factory=list, description="Files that carry the suspicious content (empty for benign).")
    indicator_ids: list[str] = Field(
        default_factory=list,
        description="ids of the deterministic indicator hits you relied on (CITATIONS; the system "
        "attaches the FULL set of hits on read — you cannot add, hide, or invent hits here).",
    )
    recommended_action: str = Field(
        "allow", description="allow | flag-for-review | block-merge — your recommended gate.")

    @classmethod
    def from_payload(cls, out: dict) -> "ChangeVerdict":
        """Coerce a stored result-event `output` into a ChangeVerdict, healing legacy/loose shapes.
        Extra keys a stray planner emitted (e.g. an `indicators` list it tried to author) are ignored
        by pydantic — `assemble_verdict` re-sources the real hits from the trace."""
        return cls(**out)


# ── the ASSEMBLED verdict: judgement + the SYSTEM-owned deterministic evidence ────────────────────

class AssembledVerdict(BaseModel):
    """The planner's `ChangeVerdict` PLUS the deterministic fields the SYSTEM fills (never the planner):
    the UNION of all indicator hits from the trace, the derived max severity, whether to signal, and any
    cited-but-missing indicator ids (a fabrication tell). Produced by `assemble.assemble_verdict`."""

    verdict: str
    confidence: float
    summary: str
    rationale: str
    techniques: list[str] = Field(default_factory=list)
    suspect_files: list[str] = Field(default_factory=list)
    recommended_action: str = "allow"

    indicators: list[IndicatorHit] = Field(
        default_factory=list, description="ALL deterministic hits (baseline ∪ tool calls), re-sourced.")
    max_indicator_severity: str = Field(
        "info", description="Highest severity across `indicators` — DERIVED, never self-reported.")
    signal: bool = Field(
        False,
        description="Whether this run should emit a SIEM signal — DERIVED: the planner's verdict OR a "
        "deterministic high/critical indicator (so a benign self-report can't suppress hard evidence).",
    )
    cited_unknown_ids: list[str] = Field(
        default_factory=list, description="indicator_ids the planner cited that match NO recorded hit.")


# ── API response shape (OpenAI-Responses-flavored serialization of a run) ──────────────────────────

class RefusalInfo(BaseModel):
    """Populated INSTEAD of a verdict when the run could not classify — an INFORMATIVE failure."""

    reason: str = Field(..., description="Machine-readable category, e.g. run_failed / cancelled / inconclusive.")
    detail: str
    indicators: list[IndicatorHit] = Field(
        default_factory=list, description="Deterministic hits still gathered even though no verdict landed.")


class ProcessInfo(BaseModel):
    """Objective effort / transparency for the run (mirrors `rl_export.run_metrics`)."""

    steps: int = 0
    scan_calls: int = 0
    deep_classify_calls: int = 0
    deep_classify_circuit_breaks: int = 0
    analyst_calls: int = 0
    fetches: int = 0
    elapsed_s: Optional[float] = None
    hit_iteration_cap: bool = False


class RubricCriterionView(BaseModel):
    """One ATLAS criterion as PRESENTED in the response: its identity plus the deterministic FACTS
    observed for it this run. A reward-free LABEL — `observed` is never a score/met/unmet verdict
    (it is copied verbatim from `CriterionFact.observed`; see rubric.py)."""

    criterion: str
    category: str = Field(..., description="one of TF / TA / TG / PA")
    description: str = ""
    weight: float = 1.0
    observed: dict = Field(
        default_factory=dict, description="deterministic facts re-lensed from the run's own metrics; never a score"
    )


class RubricReport(BaseModel):
    """The run's ATLAS TF/TA/TG/PA rubric, presented as reward-free LABELS (see rubric.py). Presentation
    only — scoring (dᵢ∈[0,1]) is the downstream TRAINER's job; nothing here is a score. Surfacing this in
    the response/UI does NOT add information to the trajectory (the facts already ride
    `rl_export.rubric_signal`); it makes the existing labels visible."""

    categories: list[str] = Field(default_factory=lambda: list(CRITERION_CATEGORIES))
    criteria: list[RubricCriterionView] = Field(default_factory=list)
    note: str = Field(
        default="Reward-free labels: deterministic facts re-lensed from the run's own metrics, never a score."
    )


class DetectionResponse(BaseModel):
    """The API-shaped result of one run — an OpenAI-Responses-flavored envelope over the assembled
    verdict. A read-time presentation; carries NO new judgement.

    `status`: `classified` (a verdict landed) · `inconclusive` (ran but produced no usable verdict →
    `refusal` populated) · `failed` (the run did not finalize)."""

    model_config = {"protected_namespaces": ()}

    id: str
    object: str = "change.detection"
    created: int = 0
    model: dict = Field(default_factory=dict, description="The roles used: planner / analyst / classifier.")
    status: str
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    signal: bool = False
    summary: str = ""
    rationale: str = ""
    techniques: list[str] = Field(default_factory=list)
    suspect_files: list[str] = Field(default_factory=list)
    recommended_action: Optional[str] = None
    indicators: list[IndicatorHit] = Field(default_factory=list)
    max_indicator_severity: str = "info"
    source: Optional[dict] = Field(default=None, description="Echoed change metadata (repo/kind/number).")
    refusal: Optional[RefusalInfo] = None
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    rubric: Optional[RubricReport] = Field(
        default=None,
        description="ATLAS TF/TA/TG/PA reward-free LABELS for this run's trajectory (deterministic facts, never a score).",
    )
