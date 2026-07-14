"""The SSE server: two modes.

- **Replay** (`GET /v1/runs/{id}` + `/events`) — serve a finished run's structured `DetectionResponse`
  and replay its stored trace as SSE. A thin bridge over diff-sentry's per-run artifacts (`responses/`,
  `traces/`); defaults to this in-repo workspace root, override with `DS_ARTIFACTS_DIR`.
- **Live** (`POST /v1/classify`) — drive a LIVE classification via diff-sentry's `cli.run` from a change
  (a pasted payload, or a `pr`/`issue` ingested host-side via `gh`) and stream the ACTION trajectory as
  SSE (the `TraceRecorder`'s `on_event` observer; see `live.py`), ending with `detection.run.completed`
  carrying the durable `DetectionResponse`. SIEM emission is OFF (a viewer must not POST to a SIEM).

The console reads diff-sentry's trace/v1 + DetectionResponse contract; it re-implements no harness logic.
NO cancel/Stop in v1 (a classification is one short change): a terminal Ctrl+C makes uvicorn wait for the
live SSE to close (the run to finish) before exiting — set `--timeout-graceful-shutdown` as a bound.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .iterations import build_iterations, cited_unknown_ids
from .live import run_live
from .mapper import to_event

# The workspace ROOT that owns this studio/ member (parents[2] of studio/diff_sentry_studio/app.py).
REPO_ROOT = Path(__file__).resolve().parents[2]

# Where diff-sentry's runs live, resolved to an ABSOLUTE path so it is stable regardless of the process
# CWD. Default: `<root>/output` — diff-sentry's `cli` defaults `--out ./output` (and cli.run's `outdir`
# default is "./output"), so a CLI run from the repo root writes `output/{traces,responses}`; the studio's
# own live worker writes there too (it passes this dir as `outdir`). So zero-config replay-only just works
# on CLI-produced runs. `DS_ARTIFACTS_DIR` overrides to point at any other output dir / checkout.
ARTIFACTS = Path(
    os.environ.get("DS_ARTIFACTS_DIR") or REPO_ROOT / "output"
).expanduser().resolve()
# The bundled incident corpus is a REPO asset (ships with the studio), NOT a per-deployment artifact, so
# it is anchored to the repo root INDEPENDENTLY of ARTIFACTS — a `DS_ARTIFACTS_DIR` override must not empty
# the demo picker.
CORPUS = REPO_ROOT / "tests" / "corpus"
STATIC = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="diff-sentry-studio", version="0.1.0")


class _RevalidateStatic(StaticFiles):
    """Serve static assets with `Cache-Control: no-cache` so the browser ALWAYS revalidates — it still
    304s when unchanged (via the ETag StaticFiles already sends, so it's cheap). Without this the
    zero-build `app.js`/`style.css` cache indefinitely, so a shipped frontend change silently shows the
    OLD UI until a manual hard-refresh."""

    async def get_response(self, path: str, scope):  # noqa: ANN001 — Starlette's Scope type
        resp = await super().get_response(path, scope)
        resp.headers["Cache-Control"] = "no-cache"
        return resp


# The zero-build vanilla frontend (index.html + app.js + trajectory.js + style.css + the pure
# replay-core/run-core modules + a vendored font), served same-origin so no CORS. Guarded so a
# backend-only deploy without the dir still boots.
if STATIC.is_dir():
    app.mount("/static", _RevalidateStatic(directory=str(STATIC)), name="static")


@app.get("/")
def index() -> FileResponse:
    """Serve the single-page frontend shell (the detection console)."""
    idx = STATIC / "index.html"
    if not idx.exists():
        raise HTTPException(404, "frontend not present (static/index.html missing)")
    return FileResponse(str(idx), headers={"Cache-Control": "no-cache"})  # revalidate; never a stale shell


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _slug_id(raw: str) -> str:
    """A filesystem-/URL-safe id token: keep [A-Za-z0-9._-], fold the rest (incl. `/`) to '-', strip
    leading/trailing '.'/'-' so it can NEVER become a traversal segment (`..`, an absolute path, a nested
    dir). run_id embeds attacker-influenceable input (a repo string), and it becomes a file path — a
    detection console must not open a path traversal on itself."""
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", raw or "").strip("-.")
    return token or "unknown"


def _response_path(run_id: str) -> Path:
    return ARTIFACTS / "responses" / f"{_slug_id(run_id)}.json"


def _trace_path(run_id: str) -> Path:
    return ARTIFACTS / "traces" / f"{_slug_id(run_id)}.jsonl"


def _step_key(event: dict) -> int:
    s = str(event.get("step_id", ""))
    return int(s) if s.lstrip("-").isdigit() else 1 << 30


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


@app.get("/v1/config")
def config() -> JSONResponse:
    """The three model ROLES → their configured model names (from env), so the UI can show them on page
    load. Read env DIRECTLY (never `DetectConfig.from_env`, which RAISES without DS_ROOT_LM/DS_SUB_LM) so a
    replay-only deploy still answers. `classifier` mirrors diff-sentry's `DS_CLASSIFIER_LM or analyst`
    fallback. `classify_backend`/`emit_on`/`max_iterations`/`enable_fetch` let the UI frame the run."""
    analyst = os.environ.get("DS_SUB_LM")
    emit_on = [v.strip() for v in os.environ.get("DS_EMIT_ON", "suspicious,malicious").split(",") if v.strip()]
    return JSONResponse({
        "models": {
            "planner": os.environ.get("DS_ROOT_LM"),
            "analyst": analyst,
            "classifier": os.environ.get("DS_CLASSIFIER_LM") or analyst,
        },
        "classify_backend": os.environ.get("DS_CLASSIFY_BACKEND", "self"),
        "max_iterations": int(os.environ.get("DS_MAX_ITERATIONS", "25")),
        "emit_on": emit_on,
        "enable_fetch": (os.environ.get("DS_ENABLE_FETCH", "").strip().lower() in {"1", "true", "yes", "on"}),
    })


@app.get("/v1/runs")
def list_runs() -> JSONResponse:
    """Run ids that have a stored response, sorted — feeds the Load picker so the user can discover what
    is loadable instead of guessing a run id."""
    d = ARTIFACTS / "responses"
    runs = sorted((p.stem for p in d.glob("*.json")), key=lambda s: s.lower()) if d.is_dir() else []
    return JSONResponse({"runs": runs})


@app.get("/v1/fixtures")
def fixtures() -> JSONResponse:
    """The bundled hackerbot-claw incident events as ready-made demo inputs — one click loads a real
    reconstructed attack into the classify box, with its `expected_signal`/`expected_rules` so the UI can
    show expected-vs-actual. Read-only, from `tests/corpus/`. `{fixtures: []}` when the corpus is absent
    (a packaged deploy without the repo tree)."""
    p = CORPUS / "hackerbot_claw_incident.json"
    if not p.exists():
        return JSONResponse({"fixtures": []})
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a malformed corpus must not 500 the console
        return JSONResponse({"fixtures": []})
    out = [{"name": e.get("name"), "incident_ref": e.get("incident_ref"), "note": e.get("note"),
            "expected_signal": e.get("expected_signal"), "expected_rules": e.get("expected_rules"),
            "event": e.get("event")}
           for e in (data.get("entries") or [])]
    return JSONResponse({"fixtures": out})


@app.get("/v1/runs/{run_id}")
def get_run(run_id: str) -> JSONResponse:
    """The durable, structured `DetectionResponse` for a finished run, AUGMENTED with `cited_unknown_ids`
    (the planner's fabricated citations — re-derived from the trace, since the response envelope omits it;
    see iterations.cited_unknown_ids). Missing trace → `[]` (no fabrication tell available)."""
    p = _response_path(run_id)
    if not p.exists():
        raise HTTPException(404, f"no response for run {run_id!r}")
    try:
        resp = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:  # a corrupt/half-written response file must not 500 opaquely
        raise HTTPException(502, f"stored response for run {run_id!r} is unreadable: {e}") from e
    tp = _trace_path(run_id)
    resp["cited_unknown_ids"] = cited_unknown_ids(_load_events(tp)) if tp.exists() else []
    return JSONResponse(resp)


@app.get("/v1/runs/{run_id}/iterations")
def get_iterations(run_id: str) -> JSONResponse:
    """The per-iteration trajectory breakdown — planner reasoning + REPL code/output + each turn's tool
    calls + timing — behind the Trajectory drawer. Built from the stored trace, read-only."""
    p = _trace_path(run_id)
    if not p.exists():
        raise HTTPException(404, f"no trace for run {run_id!r}")
    return JSONResponse(build_iterations(_load_events(p)))


@app.get("/v1/runs/{run_id}/events")
async def stream_run(run_id: str, delay: float = 0.0) -> StreamingResponse:
    """Replay the run's trace as SSE — the process build-up. `delay` (seconds) paces it to feel live.
    Wait for `detection.run.completed`, then GET `/v1/runs/{run_id}` for the full result."""
    p = _trace_path(run_id)
    if not p.exists():
        raise HTTPException(404, f"no trace for run {run_id!r}")
    # Sort by step_id (matches diff-sentry's read order). Ordering caveat: tool_calls are written live but
    # `main_step`s flush post-hoc with trailing step_ids, so a REPLAY streams the action timeline first,
    # then the reasoning turns — the stored trace does not preserve true think→act interleaving.
    events = sorted(_load_events(p), key=_step_key)

    async def gen():
        saw_completed = False
        for event in events:
            out = to_event(event)
            if out is None:
                continue
            if out["event"] == "detection.run.completed":
                saw_completed = True
            yield _sse(out["event"], out["data"])
            if delay:
                await asyncio.sleep(delay)
        if not saw_completed:
            # The trace never finalized — no `run_end` (e.g. a hard-killed run: SIGKILL skips the
            # recorder's __exit__, truncating the JSONL). Still close the replay with the terminal event,
            # so the client GETs the stored response instead of waiting forever "Classifying…".
            yield _sse("detection.run.completed", {})

    return StreamingResponse(gen(), media_type="text/event-stream")


class ClassifyRequest(BaseModel):
    """One live run's request. `mode`: `classify` (a pasted change `payload`), `pr`/`issue` (ingest
    `repo`+`number` host-side via `gh`). `run_id` names the artifacts; when absent it is derived +
    sanitized. `overwrite` guards a re-classify from silently clobbering a finalized run."""
    mode: str = "classify"                # classify | pr | issue
    repo: str | None = None
    number: int | None = None
    payload: dict | None = None
    run_id: str | None = None
    overwrite: bool = False


def _derive_run_id(req: "ClassifyRequest") -> str:
    """The run id, sanitized (it becomes a file path). Mirrors `cli.py`: pr → `<repo->-pr-<n>`, issue →
    `<repo->-issue-<n>`, classify → `<repo->-<number>` (from the payload)."""
    if req.run_id and req.run_id.strip():
        return _slug_id(req.run_id.strip())
    payload = req.payload or {}
    repo = req.repo or payload.get("repo") or "change"
    if req.mode == "pr":
        base = f"{repo}-pr-{req.number}"
    elif req.mode == "issue":
        base = f"{repo}-issue-{req.number}"
    else:
        base = f"{repo}-{payload.get('number', 0)}"
    return _slug_id(base)


@app.post("/v1/classify")
async def classify(req: ClassifyRequest) -> StreamingResponse:
    """Drive a LIVE classification and stream its ACTION trajectory as SSE, ending with
    `detection.run.completed` carrying the durable `DetectionResponse`. The run executes in a worker
    thread (it has blocking parts); the `on_event` observer pushes events onto a thread-safe queue this
    coroutine drains. The run writes the usual diff-sentry artifacts (so it is later GET-replayable).
    409 if a FINALIZED run already owns this run_id and `overwrite` is not set — diff-sentry's `run`
    resets the trace per run_id, so a re-classify would clobber the stored response/trace."""
    run_id = _derive_run_id(req)
    if not req.overwrite and _response_path(run_id).exists():
        raise HTTPException(409, f"run {run_id!r} already exists — pass overwrite=true to replace it")
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    done = object()

    def sink(event: dict) -> None:                       # called from the worker thread
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def on_done(final: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, {"event": "detection.run.completed", "data": final})
        loop.call_soon_threadsafe(queue.put_nowait, done)

    request = req.model_dump(exclude={"run_id", "overwrite"})
    worker = threading.Thread(target=run_live, args=(request, run_id, sink, on_done),
                              kwargs={"artifacts_dir": ARTIFACTS}, daemon=True)
    worker.start()

    async def stream():
        yield _sse("detection.run.created", {"run_id": run_id})
        while True:
            item = await queue.get()
            if item is done:
                break
            yield _sse(item["event"], item["data"])

    return StreamingResponse(stream(), media_type="text/event-stream")
