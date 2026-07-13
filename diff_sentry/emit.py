"""Host-side SIEM emitter — the "emit a signal into a SIEM" stage, run AFTER the RLM finalizes.

Emitting a signal is DETERMINISTIC plumbing, not an agentic decision, so it runs HOST-SIDE outside the
trajectory — the planner never gets SIEM credentials and the POST never appears as a tool call (the same
reasoning that keeps the cve-reverser publish step host-side). A signal is emitted only when the
assembled response says so (`response.signal`, derived deterministically in `assemble`) AND the config
carries a webhook. The transport is injectable (`poster`) so this is unit-testable with no network; the
whole call is guarded so a SIEM outage can never sink an already-finished classification.

The signal PAYLOAD is a compact, machine-readable subset of the `DetectionResponse` — a Datadog Cloud
SIEM / Splunk-HEC / generic-webhook consumer builds detection rules on it. Pure stdlib + httpx; no dspy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .config import DetectConfig
from .schema import DetectionResponse

# A poster maps (url, headers, json_payload) to an HTTP status code. Sync — this runs host-side, but a
# sync seam keeps it symmetric with the rest and trivially fakeable in tests.
Poster = Callable[[str, dict, dict], int]


@dataclass
class EmitResult:
    emitted: bool                     # a POST was actually sent
    status_code: Optional[int] = None
    skipped_reason: Optional[str] = None   # why nothing was sent (no signal / no webhook / disabled)
    error: Optional[str] = None       # a transport error (the run still stands; this is best-effort)


def signal_payload(response: DetectionResponse) -> dict:
    """The compact SIEM signal — verdict, severity, techniques, and the deterministic indicators."""
    return {
        "run_id": response.id,
        "source": response.source or {},
        "verdict": response.verdict,
        "confidence": response.confidence,
        "recommended_action": response.recommended_action,
        "max_indicator_severity": response.max_indicator_severity,
        "techniques": response.techniques,
        "suspect_files": response.suspect_files,
        "summary": response.summary,
        "indicators": [
            {"id": h.id, "rule": h.rule, "severity": h.severity, "title": h.title, "location": h.location}
            for h in response.indicators
        ],
    }


def _httpx_poster(timeout: float) -> Poster:
    def post(url: str, headers: dict, payload: dict) -> int:
        import httpx
        resp = httpx.post(url, headers=headers, json=payload, timeout=timeout)
        return resp.status_code

    return post


def emit_signal(
    response: DetectionResponse, config: DetectConfig, *, poster: Optional[Poster] = None,
    timeout: float = 15.0,
) -> EmitResult:
    """Emit the SIEM signal for a finished run, if the response says to and a webhook is configured.

    Returns an `EmitResult` describing what happened; NEVER raises (a SIEM outage must not crash a run)."""
    if not response.signal:
        return EmitResult(emitted=False, skipped_reason="no_signal")
    if not config.can_emit:
        return EmitResult(emitted=False, skipped_reason="no_webhook")
    headers = {"Content-Type": "application/json"}
    if config.siem_token:
        headers["Authorization"] = f"Bearer {config.siem_token}"
    post = poster or _httpx_poster(timeout)
    try:
        code = post(config.siem_webhook_url, headers, signal_payload(response))
    except Exception as exc:  # noqa: BLE001 — best-effort; the finished run is the source of truth
        return EmitResult(emitted=False, error=f"{type(exc).__name__}: {exc}")
    return EmitResult(emitted=True, status_code=code)
