"""Output models for diff-sentry (the RLMTask's validated output + the assembled result + the API shape).

The load-bearing convention (inherited from the rlm-harness consumers): the planner SUBMITs JUDGEMENT only.
The authoritative EVIDENCE (the deterministic indicator hits a signal is built on) is NEVER the
planner's to write. `scan_indicators` records its structured hits into the trace (and a host-side
BASELINE scan lands in the run_start meta), and the SYSTEM re-sources the FULL UNION of those hits on
read (`assemble.assemble_verdict`). The planner may only CITE hit ids (`indicator_ids`); it cannot
suppress evidence by omitting it, and it cannot invent it (a cited id with no matching hit is flagged).

Pure pydantic; no dspy; trivially unit-testable.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel, Field, field_validator

# reward-free rubric TYPES: rlm-harness's shared, taxonomy-agnostic primitives, re-exported so
# `from .schema import Criterion, ...` resolves here.
from rlm_harness.rubric import Criterion, CriterionFact, RubricCriteria  # noqa: F401 (re-export)

# ─── ATLAS rubric (a rollout LABEL surface, never a reward) ────────────────────────────────────
# The four ATLAS criterion categories: Task Fulfillment, Tool Appropriateness, Tool Grounding,
# Parameter Accuracy. The rubric TYPES above are rlm-harness's (category is opaque to the kit); diff-sentry
# owns only this ATLAS category set + the criterion descriptions + the lens (see rubric.py). The rubric is
# carried in run_start meta as LABELS; scoring (dᵢ∈[0,1]) is the downstream TRAINER's job, never here.
CRITERION_CATEGORIES = ("TF", "TA", "TG", "PA")


# The allowed verdict labels + the ranked severities, kept as plain data so deterministic code
# (assemble/response) can compare them without importing an enum machinery the model must satisfy.
VERDICTS = ("benign", "suspicious", "malicious")
# The SANCTIONED "cannot ground a confident call" outcome: a principled negative OUTCOME, NOT a reward.
# A content-free / unfetchable / not-actually-a-change input lands here instead of a confident verdict;
# `response` maps it to `status="inconclusive"` + `RefusalInfo(reason="insufficient_evidence")`. It is
# NOT in the default `emit_on`, so it never forces a SIEM signal (hard indicator evidence still can).
INCONCLUSIVE_VERDICT = "inconclusive"
# The full set of legitimate SUBMIT / second-stage verdict labels (the 3 DECISIVE verdicts + inconclusive).
SUBMIT_VERDICTS = VERDICTS + (INCONCLUSIVE_VERDICT,)
SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# The deterministic severity floor: a hit AT OR ABOVE this forces a SIEM signal regardless of the
# planner's verdict, so a false-benign self-report can't suppress hard evidence (MF3). Shared by the
# live assemble path AND the crash/failed path so they can never diverge.
SIGNAL_SEVERITY_FLOOR = "high"


def severity_rank(sev: str) -> int:
    """Rank a severity string (unknown → -1, below `info`)."""
    return _SEV_RANK.get((sev or "").strip().lower(), -1)


def at_signal_floor(sev: str) -> bool:
    """Whether a severity is at or above the deterministic signal floor. THE predicate: the live assemble path,
    the crash/screen path and the actor store all ask it, so the floor cannot be re-derived differently."""
    return severity_rank(sev) >= severity_rank(SIGNAL_SEVERITY_FLOOR)


def max_severity(sevs) -> str:
    """The highest severity in `sevs`, or "info" when empty/unknown: a deterministic reduction."""
    best, best_rank = "info", -1
    for s in sevs:
        r = severity_rank(s)
        if r > best_rank:
            best, best_rank = (s or "").strip().lower(), r
    return best if best_rank >= 0 else "info"


def floor_severity(hits) -> str:
    """The highest severity among GROUNDED hits: what the signal floor reads (`floor_indicator_severity`). A
    hit minted on text the planner wrote itself is evidence of nothing in the change."""
    return max_severity([h.severity for h in hits if getattr(h, "grounded", True)])


# ── the deterministic evidence layer (produced by indicators.scan_indicators, NEVER the planner) ──

class IndicatorHit(BaseModel):
    """One deterministic detector hit: a FACT the scanner recorded, not a model opinion.

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
    decoded: str | None = Field(default=None, description="Decoded payload when the rule de-obfuscated one.")
    via: str = Field(
        "", description="The login whose COMMENT carried the text this hit fired on, else empty. A structured "
        "field, not a substring of `location` (a file path is free-form and could be named to match), so the "
        "actor store attributes a comment to its writer and never to the change's author.")
    grounded: bool = Field(
        True, description="Whether the scanned text came from the change: the host-side baseline always did; a "
        "planner scan did when its region is in the change, or was decoded from a span of it or from a value an "
        "earlier grounded scan of the run held. An ungrounded hit stays in the evidence but never reaches the "
        "signal floor (text the planner wrote itself).")

    @field_validator("title", "evidence", "location", "decoded", "via")
    @classmethod
    def _encodable(cls, value: str | None) -> str | None:
        """The text without lone surrogates. A JSON escape such as `\\ud800` in a change decodes to one, and a hit that held it could not be serialized: the change it came from
        would be lost with it."""
        return None if value is None else value.encode("utf-8", "replace").decode("utf-8")

    def model_copy(self, *, update: dict[str, Any] | None = None, deep: bool = False) -> IndicatorHit:
        """A copy whose updated fields go through the same validation as a new hit (`model_copy` alone skips it, and the copy of a hit whose location or `via` holds a lone surrogate could not be encoded)."""
        copy = super().model_copy(update=update, deep=deep)
        return IndicatorHit(**copy.model_dump()) if update else copy


# ── the planner's SUBMIT: JUDGEMENT only (the RLMTask output_model) ───────────────────────────────

class ChangeVerdict(BaseModel):
    """What the PLANNER submits — JUDGEMENT only. Carries NO raw diff bytes and NO indicator hits.

    `indicator_ids` are CITATIONS (which deterministic hits the planner leaned on), validated on read;
    they never gate which hits reach the signal — `assemble_verdict` unions ALL hits from the trace.
    """

    summary: str = Field(..., description="One or two sentences: what the change is and the call you made.")
    verdict: str = Field(
        ..., description="benign | suspicious | malicious | inconclusive — your classification of INTENT. "
        "Use `inconclusive` ONLY when the change carries no assessable content (empty / unfetchable / not "
        "an actual change) — a real, groundable change (even a hard one) gets a decisive call.")
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
    def from_payload(cls, out: dict) -> ChangeVerdict:
        """Coerce a stored result-event `output` into a ChangeVerdict, healing legacy/loose shapes.
        Extra keys a stray planner emitted (e.g. an `indicators` list it tried to author) are ignored
        by pydantic; `assemble_verdict` re-sources the real hits from the trace."""
        return cls(**out)


# How many `inconclusive` SUBMITs a run on a groundable change refuses before the next one stands. dspy hands a refused
# SUBMIT back to the planner as the step's output, so it decides in the same trajectory.
_INCONCLUSIVE_REFUSALS = 2
_SubmittedVerdict = ChangeVerdict
# Off while dspy's extract fallback writes the verdict at the iteration cap: no planner turn is left to answer a
# refusal there, and the parse failure would fail the run.
_REFUSING = contextvars.ContextVar("diff_sentry_refusing_inconclusive", default=True)


@contextlib.contextmanager
def no_refusal() -> Iterator[None]:
    token = _REFUSING.set(False)
    try:
        yield
    finally:
        _REFUSING.reset(token)


def decisive_verdict_model(facts: str, refusals: int = _INCONCLUSIVE_REFUSALS) -> type[ChangeVerdict]:
    """`ChangeVerdict` for a change that has content to read: an `inconclusive` verdict is refused `refusals` times
    with a message naming that content (`facts`), except under `no_refusal`. Same name, fields and schema.
    A planner whose own long print comes back cut can read the cut as a truncated change and SUBMIT `inconclusive`
    on a large PR."""
    left = [refusals]

    class ChangeVerdict(_SubmittedVerdict):  # the name dspy's signature resolves
        __doc__ = _SubmittedVerdict.__doc__

        @field_validator("verdict")
        @classmethod
        def _decisive(cls, value: str) -> str:
            if str(value).strip().lower() == INCONCLUSIVE_VERDICT and left[0] > 0 and _REFUSING.get():
                left[0] -= 1
                raise ValueError(
                    f"refused: this change has content to classify ({facts}), so `inconclusive` does not apply; it "
                    "is only for a change with nothing to read. An earlier output that says `characters omitted` "
                    "was YOUR print cut short, not the change: read `event` in smaller slices. "
                    "SUBMIT benign, suspicious or malicious; a low `confidence` says you are unsure.")
            return value

    return ChangeVerdict


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
    floor_indicator_severity: str = Field(
        "info", description="Highest severity across the GROUNDED `indicators` — what the signal floor reads.")
    signal: bool = Field(
        False,
        description="Whether this run should emit a SIEM signal — DERIVED: the planner's verdict OR a "
        "grounded high/critical indicator (so a benign self-report can't suppress hard evidence).",
    )
    cited_unknown_ids: list[str] = Field(
        default_factory=list, description="indicator_ids the planner cited that match NO recorded hit.")


# ── API response shape (OpenAI-Responses-flavored serialization of a run) ──────────────────────────

class RefusalInfo(BaseModel):
    """Populated INSTEAD of a verdict when the run could not classify: an INFORMATIVE failure."""

    reason: str = Field(..., description="Machine-readable category: run_failed / inconclusive / insufficient_evidence / not_escalated.")
    detail: str
    indicators: list[IndicatorHit] = Field(
        default_factory=list, description="Deterministic hits still gathered even though no verdict landed.")


class ProcessInfo(BaseModel):
    """Objective effort / transparency for the run (mirrors `rl_export.run_metrics`)."""

    steps: int = 0
    scan_calls: int = 0
    deep_classify_calls: int = 0
    deep_classify_circuit_breaks: int = 0
    analyst_calls: int = 0                  # escalations that got a response
    analyst_failures: int | None = None     # provider-refused; None when the trace cannot say
    fetches: int = 0
    elapsed_s: float | None = None
    hit_iteration_cap: bool = False


class RubricCriterionView(BaseModel):
    """One ATLAS criterion as PRESENTED in the response: its identity plus the deterministic FACTS
    observed for it this run. A reward-free LABEL: `observed` is never a score/met/unmet verdict
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
    only; scoring (dᵢ∈[0,1]) is the downstream TRAINER's job; nothing here is a score. Surfacing this in
    the response/UI does NOT add information to the trajectory (the facts already ride
    `rl_export.rubric_signal`); it makes the existing labels visible."""

    categories: list[str] = Field(default_factory=lambda: list(CRITERION_CATEGORIES))
    criteria: list[RubricCriterionView] = Field(default_factory=list)
    note: str = Field(
        default="Reward-free labels: deterministic facts re-lensed from the run's own metrics, never a score."
    )


class DetectionResponse(BaseModel):
    """The API-shaped result of one run: an OpenAI-Responses-flavored envelope over the assembled
    verdict. A read-time presentation; carries NO new judgement.

    `status`: `classified` (a verdict landed) · `inconclusive` (finalized without a usable verdict, with the
    sanctioned `inconclusive` verdict, or over an ungroundable change → `refusal` populated) · `failed`
    (the run did not finalize)."""

    model_config = {"protected_namespaces": ()}

    id: str
    object: str = "change.detection"
    created: int = 0
    model: dict = Field(default_factory=dict, description="The roles used: planner / analyst / classifier.")
    status: str
    verdict: str | None = None
    confidence: float | None = None
    signal: bool = False
    summary: str = ""
    rationale: str = ""
    techniques: list[str] = Field(default_factory=list)
    suspect_files: list[str] = Field(default_factory=list)
    recommended_action: str | None = None
    indicators: list[IndicatorHit] = Field(default_factory=list)
    max_indicator_severity: str = "info"
    # None in a stored response that predates the field, where every hit counted: read it as the max there.
    floor_indicator_severity: str | None = None
    source: dict | None = Field(default=None, description="Echoed change metadata (repo/kind/number).")
    refusal: RefusalInfo | None = None
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    rubric: RubricReport | None = Field(
        default=None,
        description="ATLAS TF/TA/TG/PA reward-free LABELS for this run's trajectory (deterministic facts, never a score).",
    )
