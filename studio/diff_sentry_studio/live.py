"""Live-run event capture: turn a running diff-sentry classification into the public SSE stream.

diff-sentry's `cli.run` exposes an `on_event` observer (the `TraceRecorder`'s per-record hook) and an
`outdir` param, so the studio streams the run's ACTIONS live and writes artifacts where the GET endpoints
read them — WITHOUT any change to the harness (a consumer extends, it never forks). The one honest gap:
`main_step` reasoning flushes post-hoc (as a trailing burst through the SAME `on_event`), so the live
feed carries the tool/analyst ACTION stream (scan / classify / analyst / fetch / skill), not live
reasoning. Reasoning is available in the Trajectory drawer (replay over the stored trace). Streaming live
reasoning would need a rlm-kit change (forward the main-step preview to `on_event` as each turn parses),
promoted into the kit for every consumer — NOT a consumer-side callbacks passthrough.

`run_live` is SYNCHRONOUS — call it in a worker thread; the FastAPI layer wires `sink`/`on_done` to a
thread-safe queue. `on_done` is ALWAYS called exactly once — even if importing diff_sentry fails (the
`live` extra was not installed) — so the SSE stream completes with an informative `failed` response
instead of the worker thread dying silently and leaving the client hung.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

from .mapper import to_event


def trace_event_sink(sink: Callable[[dict], None]) -> Callable[[dict], None]:
    """Build a `TraceRecorder` `on_event` observer that maps `tool_call`/`sub_call` trace events →
    public SSE events (via the shared `mapper.to_event`) and pushes them to `sink`, live. Skips
    `main_step` (it flushes post-hoc as a trailing burst — surfacing it would misrepresent the timeline)
    and run_start/run_end/result (the endpoint owns `created`/`completed`)."""

    def on_event(event: dict) -> None:
        if event.get("type") in ("tool_call", "sub_call"):
            out = to_event(event)
            if out:
                sink(out)

    return on_event


def _quiet_litellm_aiohttp() -> None:
    """litellm (dspy's LM backend, via rlm-kit) defaults to an aiohttp transport whose pooled
    ClientSession is bound to the per-run `asyncio.run` loop; when that loop closes — run finished — aiohttp
    logs a noisy "Unclosed connector" through the loop's exception handler. Force litellm onto httpx: no
    aiohttp session is created, so nothing dangles. One process-global flag, best-effort — a replay-only
    install has no litellm, and a flag rename just no-ops."""
    try:
        import litellm
        litellm.disable_aiohttp_transport = True
    except Exception:  # noqa: BLE001 — litellm absent (replay-only) or attribute gone; nothing to quiet
        pass


def _build_event(request: dict, *, ingest=None) -> dict:
    """Build the diff-sentry change-event dict this run classifies, from the studio request. `mode`:
    `classify` (a pasted `payload` → `event_from_payload`), `pr`/`issue` (`repo`+`number` → host-side
    `gh` ingest). `ingest` is injectable so tests skip the diff_sentry import / the `gh` shell-out."""
    mode = request.get("mode") or "classify"
    if ingest is None:
        from diff_sentry import ingest as ingest  # noqa: PLC0414 — lazy; absent on a replay-only install
    if mode == "pr":
        return ingest.pr_event(request["repo"], int(request["number"]))
    if mode == "issue":
        return ingest.issue_event(request["repo"], int(request["number"]))
    return ingest.event_from_payload(request.get("payload") or {})


def run_live(
    request: dict,
    run_id: str,
    sink: Callable[[dict], None],
    on_done: Callable[[dict], None],
    *,
    artifacts_dir=None,
    cli_run: Callable | None = None,
    ingest=None,
    build_failed_response: Callable | None = None,
) -> None:
    """Run ONE classification with the live ACTION stream attached — `sink(event)` fires for each
    tool/analyst call as it is recorded, then `on_done(response_dict)` with the durable response (or a
    `status=failed` refusal on error). `request` is the studio's classify request (`mode` + payload or
    repo/number). `cli_run`/`ingest`/`build_failed_response` are injected for tests; default to
    diff-sentry's `cli.run` (THE programmatic entry — never a fork) and `response.build_failed_response`.

    SIEM emission is OFF (`emit=False`): the console SHOWS the signal decision, but a viewer must not POST
    to a real SIEM as a side effect. `on_done` is ALWAYS called once (see module docstring)."""
    try:
        _quiet_litellm_aiohttp()   # process-global: keep litellm off aiohttp so no connector dangles
        # diff_sentry imports stay INSIDE the try: a missing `live` extra (no diff_sentry) must become a
        # `failed` response, not an uncaught exception that kills the thread before `on_done`.
        event = _build_event(request, ingest=ingest)
        _cli_run = cli_run
        if _cli_run is None:
            from diff_sentry.cli import run as _cli_run
        # diff-sentry writes artifacts to `outdir`-relative paths (no chdir hack needed, unlike the
        # siblings); point it at the studio's artifacts dir so live artifacts land where the GET endpoints
        # read them. emit=False: the studio never POSTs to a real SIEM.
        arts = _cli_run(event, run_id=run_id, outdir=str(artifacts_dir or "./output"),
                        on_event=trace_event_sink(sink), emit=False)
        on_done(_final_response(arts, run_id, build_failed_response))
    except Exception as exc:  # noqa: BLE001 — any run failure becomes an informative `failed` response
        on_done(_failed_dict(run_id, _describe_exc(exc), build_failed_response))


def _final_response(arts, run_id: str, build_failed_response) -> dict:
    """The durable response dict for a finished run. diff-sentry writes `responses/{run_id}.json` for
    EVERY outcome — classified, inconclusive, failed — so PREFER that on-disk artifact: it is exactly what
    a later GET-replay serves. Fall back to a failed dict when no file was written (a test's fake
    cli_run that writes nothing, or a run that produced no artifacts)."""
    path = getattr(arts, "response_path", None)
    if path and os.path.exists(path):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — unreadable/partial file; fall through to a failed dict
            pass
    return _failed_dict(run_id, "The run finalized without a readable response artifact.",
                        build_failed_response)


def _describe_exc(exc: BaseException) -> str:
    """One line describing a run failure, INCLUDING its underlying cause. `RLMTaskError` reports the
    opaque "Failed to produce a valid 'result' after N attempts"; the real reason (a planner-endpoint
    error, an adapter parse failure) is on `__cause__`. Surfacing it stops an infra hiccup from reading
    like a content/schema problem (diff-sentry's own CLAUDE.md: an RLMTaskError is almost always infra)."""
    out = f"{type(exc).__name__}: {exc}"
    cause = exc.__cause__ or exc.__context__
    if cause is not None and cause is not exc:
        out += f" — caused by {type(cause).__name__}: {str(cause)[:300]}"
    return out


def _failed_dict(run_id: str, detail: str, build_failed_response: Callable | None) -> dict:
    """Build a `status=failed` response dict. Prefer diff-sentry's `build_failed_response` (it still
    carries any deterministic indicators gathered + the derived signal), but fall back to a minimal
    literal when diff_sentry itself is unavailable (the import that just failed) so the stream completes."""
    try:
        bfr = build_failed_response
        if bfr is None:
            from diff_sentry.response import build_failed_response as bfr  # noqa: PLC0414
        return bfr(run_id, [], detail).model_dump()
    except Exception:  # noqa: BLE001 — diff_sentry missing; emit a self-contained failure
        return {
            "id": run_id, "object": "change.detection", "status": "failed",
            "summary": "the live run could not start", "signal": False,
            "refusal": {"reason": "run_failed", "detail": detail, "indicators": []},
            "indicators": [], "max_indicator_severity": "info", "process": {},
        }
