"""The second-stage classifier tool — the SEAM designed to be swapped to a stronger/dedicated backend.

`make_deep_classify_tool` builds the `deep_classify` tool from a `chat_fn` via rlm-kit's `make_model_tool`
(chat + transient-retry + validate + circuit-breaker). The planner CHOOSES to consult it on an ambiguous
change, so the call lands in the trajectory as a `tool_call` — the correct rlm-kit shape for a second
model-JUDGEMENT (it must be a tool, not the sub-LM: a model grading the change is an agentic decision).

- `classify_backend="self"` (now, default): a general model returns a structured verdict as JSON.
- A dedicated/stronger backend later: only `_selfclassify_chat` changes; the planner, schema, assemble,
  and export are untouched — a localized swap. That is the whole point of routing stage-2 through one
  `chat_fn`.

The chat call is injectable (`chat_fn`) so the pipeline is testable without a live endpoint. Sync — dspy
invokes tools synchronously.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from rlm_kit.tools import make_model_tool
from rlm_kit.trace import record_tool_call

from .config import DetectConfig
from .schema import SUBMIT_VERDICTS


@dataclass
class ClassifyValidation:
    """The validator's verdict over the classifier's raw output — `.ok` / `.errors` for make_model_tool,
    plus the parsed structured fields the caller surfaces to the planner."""

    ok: bool
    errors: list[str] = field(default_factory=list)
    verdict: str = ""
    confidence: float = 0.0
    rationale: str = ""
    techniques: list[str] = field(default_factory=list)


def _parse_classifier_json(raw: str) -> ClassifyValidation:
    """Deterministically validate the classifier's structured output: it must be JSON with a known
    `verdict`. A malformed/off-schema reply is `ok=False` so the planner re-asks or falls back — never
    a silent bad verdict."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[1] if "\n" in text else text
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return ClassifyValidation(ok=False, errors=["no JSON object in classifier output"])
    try:
        obj = json.loads(text[start:end + 1])
    except ValueError as exc:
        return ClassifyValidation(ok=False, errors=[f"invalid JSON: {exc}"])
    verdict = str(obj.get("verdict", "")).strip().lower()
    # SUBMIT_VERDICTS = the 3 decisive verdicts + the sanctioned `inconclusive` outcome, so a deep
    # escalation on a content-free / ungroundable change can also decline to a confident call.
    if verdict not in SUBMIT_VERDICTS:
        return ClassifyValidation(ok=False, errors=[f"verdict {verdict!r} not in {SUBMIT_VERDICTS}"])
    try:
        confidence = float(obj.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    techniques = obj.get("techniques") or []
    if not isinstance(techniques, list):
        techniques = [str(techniques)]
    return ClassifyValidation(ok=True, verdict=verdict, confidence=max(0.0, min(1.0, confidence)),
                              rationale=str(obj.get("rationale", "")), techniques=[str(t) for t in techniques])


def _selfclassify_chat(config: DetectConfig) -> Callable[[str], str]:
    """The `classify_backend="self"` chat: a general model returns a structured verdict on its
    OpenAI-compatible API. Lazy openai import so tests need not install it."""

    def chat(findings: str) -> str:
        from openai import OpenAI

        client = OpenAI(
            base_url=config.classifier_base_url,
            api_key=config.classifier_api_key or "EMPTY",
            timeout=config.classifier_timeout,
            max_retries=0,  # our own transient-retry loop owns retries; keep the timeout a HARD ceiling
        )
        resp = client.chat.completions.create(
            model=config.classifier_model,
            messages=[
                {"role": "system", "content": config.classifier_system_prompt},
                {"role": "user", "content": findings},
            ],
            temperature=0.1,
            max_tokens=config.classifier_max_tokens,
        )
        return resp.choices[0].message.content or ""

    return chat


def make_deep_classify_tool(config: DetectConfig, chat_fn: Optional[Callable[[str], str]] = None
                            ) -> Callable[[str], str]:
    """Build the `deep_classify` tool. The generic chat→retry→validate→circuit-break loop is rlm-kit's
    `make_model_tool`; this wrapper plugs in the backend, the JSON validator, the result message, and
    the tracing."""
    chat = chat_fn if chat_fn is not None else _selfclassify_chat(config)
    cb = config.classifier_circuit_break
    call = make_model_tool(
        chat, _parse_classifier_json,
        transient_retries=max(0, config.classifier_transient_retries),
        max_consecutive_invalid=cb if cb and cb > 0 else None,
    )

    def deep_classify(findings: str) -> str:
        """Get a SECOND-STAGE structured verdict on an ambiguous change. Pass a DISTILLED description of
        the change + the indicators found (never the whole diff). Returns the classifier's verdict +
        rationale; weigh it into your own judgement — it is an input, not a rubber stamp."""
        r = call(findings)
        if r.circuit_broken:
            record_tool_call("deep_classify", args={"findings": findings[:400]}, ok=False,
                             circuit_broken=True, errors=r.errors)
            return ("DEEP_CLASSIFY CIRCUIT BREAKER — too many unusable replies. Decide from the "
                    "deterministic indicators and your own reading; do not keep re-asking.")
        if r.endpoint_error is not None:
            record_tool_call("deep_classify", args={"findings": findings[:400]}, error=r.endpoint_error)
            return f"DEEP_CLASSIFY ENDPOINT ERROR: {r.endpoint_error}. Decide from the indicators yourself."
        v: ClassifyValidation = r.validated
        # Future SEAM swap: when the second-stage backend is a delegated rlm-kit HARNESS
        # (make_harness_tool) rather than the `self` model, its result carries
        # child_run_id/child_trace/child_meta linking THIS parent run to the child's OWN rollout. Attach
        # them here IFF present, so the child link survives the recording step. The current backend's
        # ModelToolResult has none, so `child` is empty → a NO-OP today, correct for the swap.
        child = {k: getattr(r, k) for k in ("child_run_id", "child_trace", "child_meta")
                 if getattr(r, k, None) is not None}
        record_tool_call("deep_classify", args={"findings": findings[:400]}, ok=v.ok, raw=r.raw,
                         verdict=v.verdict, confidence=v.confidence, techniques=v.techniques,
                         errors=v.errors, **child)
        if not v.ok:
            return ("DEEP_CLASSIFY returned an unusable (non-JSON / off-schema) reply — errors: "
                    + "; ".join(v.errors) + ". Decide from the deterministic indicators and your reading.")
        return (f"second-stage verdict: {v.verdict} (confidence {v.confidence:.2f})\n"
                f"techniques: {', '.join(v.techniques) or 'none'}\nrationale: {v.rationale}")

    return deep_classify
