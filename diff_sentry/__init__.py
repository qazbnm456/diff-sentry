"""diff-sentry — classify a GitHub change for malicious intent, as a traced RLM harness.

A downstream *consumer* of rlm-kit (editable path dep) reproducing Datadog's BewAIre defense shape:
ingest a GitHub PR/issue/push → analyze the diff as UNTRUSTED data in a sandboxed REPL → produce a
judgement-only structured verdict (benign/suspicious/malicious) → union the deterministic indicator
evidence on read → emit a SIEM signal host-side → export reward-free trajectories.

Public surface::

    from diff_sentry import DetectConfig, run, detect_from_event          # drive a run
    from diff_sentry import ChangeVerdict, AssembledVerdict, DetectionResponse  # shapes
    from diff_sentry import scan_indicators, assemble_verdict, build_response, emit_signal
    from diff_sentry import normalize_event, event_from_payload, export_dataset

`config`, `schema`, `normalize`, `indicators`, `assemble`, `response`, `emit`, `ingest`, `rl_export`
import NO dspy at module top (unit-testable in isolation). `ClassifyChange` / `setup` / `run` /
`detect_from_event` pull in dspy lazily (via RLMTask).
"""

from __future__ import annotations

from .assemble import assemble_verdict, verdict_from_events
from .config import DetectConfig
from .emit import EmitResult, emit_signal, signal_payload
from .indicators import hits_from_events, scan_indicators
from .ingest import event_from_payload, issue_event, pr_event
from .normalize import event_metadata, normalize_event
from .response import build_failed_response, build_response
from .rl_export import export_dataset, run_labels, run_metrics
from .schema import (
    AssembledVerdict,
    ChangeVerdict,
    DetectionResponse,
    IndicatorHit,
    ProcessInfo,
    RefusalInfo,
)

__all__ = [
    "DetectConfig",
    "ChangeVerdict",
    "AssembledVerdict",
    "IndicatorHit",
    "DetectionResponse",
    "RefusalInfo",
    "ProcessInfo",
    "scan_indicators",
    "hits_from_events",
    "normalize_event",
    "event_metadata",
    "event_from_payload",
    "pr_event",
    "issue_event",
    "assemble_verdict",
    "verdict_from_events",
    "build_response",
    "build_failed_response",
    "emit_signal",
    "signal_payload",
    "EmitResult",
    "export_dataset",
    "run_labels",
    "run_metrics",
    # dspy-bearing (lazy):
    "ClassifyChange",
    "setup",
    "run",
    "detect_from_event",
]

__version__ = "0.1.0"


def __getattr__(name: str):  # PEP 562 — defer the dspy import to first use
    if name in ("ClassifyChange", "setup"):
        from . import detect

        return getattr(detect, name)
    if name in ("run", "detect_from_event"):
        from . import cli

        return getattr(cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
