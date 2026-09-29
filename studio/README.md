# diff-sentry-studio

The web layer for [`diff-sentry`](..), shipped in-repo as a **uv workspace member**. It turns one
malicious-change classification into something a user watches happen and then reads: a live
**detection log**, the verdict framed by the **evidence** rather than the planner's self-report, the
deterministic **indicators** that fired, and the SIEM signal decision.

Two pieces:

1. An **SSE server** that serves a run's structured `DetectionResponse`, replays the run's trace as
   Server-Sent Events, and can drive ONE live classification while streaming its **action** trajectory.
2. A **web frontend**, the detection console: a change-input box (paste a payload, or ingest a PR/issue),
   a live event feed, a verdict card whose frame is keyed to the derived state (signal + evidence
   severity), the indicators as the star view, and a Trajectory drawer that replays the RLM run turn by
   turn.

The studio re-implements no diff-sentry logic: diff-sentry owns the contract and the studio serves it.
The one hard rule it honors visually is that **the card frame is derived from the deterministic evidence,
never from the planner's `verdict`**. An in-diff prompt injection can skew the verdict; it cannot skew the
unioned indicator evidence or the SIEM signal (MF3). `DESIGN.md` holds the full visual contract.

## The contract it serves

diff-sentry writes two per-run artifacts, which this server reads from `<repo-root>/output` (where the
`diff-sentry` CLI writes with its default `--out ./output`; override with `DS_ARTIFACTS_DIR`):

- `responses/{run_id}.json`: the **`DetectionResponse`** (`diff_sentry.schema`). It carries `status`
  (`classified` / `inconclusive` / `failed`), the planner's judgement-only `verdict`
  (`benign`/`suspicious`/`malicious`) and `confidence`, the **union of every indicator hit** (`indicators`:
  id/rule/severity/title/evidence/location), the derived `max_indicator_severity`, the **`signal`** boolean
  (verdict ∈ `emit_on` **OR** severity ≥ the high/critical floor, so a false-benign verdict cannot
  suppress it), `techniques`/`suspect_files`, a `recommended_action`, `process` (effort metrics), and the
  ATLAS `rubric` labels. This is the final, durable output.
- `traces/{run_id}.jsonl`: the append-only run trace. Its events are replayed as SSE and drive the
  Trajectory drawer.

**`cited_unknown_ids`** (indicator ids the planner cited that have no recorded hit, a fabrication tell) is
not in the envelope. The server re-derives it from the trace and adds it to `GET /v1/runs/{id}` (see
`iterations.cited_unknown_ids`); a missing trace yields `[]`.

Run ids become file paths and can embed an attacker-influenced repo string, so the server folds every id
to `[A-Za-z0-9._-]` before touching the filesystem.

## Endpoints

| Method | Path | Returns |
|---|---|---|
| `GET` | `/` | the detection console (zero-build vanilla page) |
| `POST` | `/v1/classify` | `text/event-stream`: **drive ONE LIVE classification**, ending with `detection.run.completed` carrying the durable `DetectionResponse`. Body `{mode, repo?, number?, payload?, run_id?, overwrite?}`: `mode=classify` runs a pasted `payload`; `mode=pr`/`issue` ingests `repo`+`number` host-side via `gh`. **409** if a finalized run already owns `run_id` and `overwrite` is not `true` (a re-classify resets the trace, which would clobber the stored run). Needs the `live` extra |
| `GET` | `/v1/fixtures` | the bundled **hackerbot-claw** incident events as one-click demo inputs, with `expected_signal`/`expected_rules` for expected-vs-actual. `{fixtures: []}` when the corpus tree is absent |
| `GET` | `/v1/runs/{run_id}` | the stored `DetectionResponse` JSON, **augmented with `cited_unknown_ids`** (404 if absent, 502 if the stored file is unreadable) |
| `GET` | `/v1/runs/{run_id}/iterations` | the per-iteration trajectory breakdown behind the Trajectory drawer |
| `GET` | `/v1/runs/{run_id}/events?delay=0.0` | `text/event-stream`: a finished run's trace **replayed** as SSE; `delay` (s) paces it |
| `GET` | `/v1/runs` | run ids that have a stored response (the Load picker) |
| `GET` | `/v1/config` | the configured model per role, the classify backend, `max_iterations`, `emit_on`, and `enable_fetch`, read straight from env so it answers even when `DS_*` is unset |

The stream carries the **process**; the result arrives with `detection.run.completed`. On the live
endpoint that event carries the full response, and the UI then re-`GET`s `/v1/runs/{id}` for the
`cited_unknown_ids` augmentation. After a replay the UI `GET`s the stored response.

## SSE event vocabulary (trace event → public event)

| trace event | SSE `event` | `data` |
|---|---|---|
| `run_start` | `detection.run.created` | replay: `{models, source, baseline, rubric}` (`baseline` = host-side hit count; `rubric` = `{categories, criteria}` count hint). Live: `{run_id}`, sent by the endpoint |
| `main_step` | `detection.plan.step` | `{turn, reasoning, has_code}` (replay only) |
| `tool_call: scan_indicators` | `detection.scan` | `{n, worst, region}` (hit count + worst severity) |
| `tool_call: deep_classify` | `detection.classify` | `{ok, verdict, confidence, circuit_broken, error, errors}` |
| `tool_call: fetch_url` | `detection.fetch` | `{url, ok, status, bytes, note}` (fetch is off by default) |
| `tool_call: read_skill`/`list_skills` | `detection.skill.read` | `{name}` |
| `tool_call` (any other tool) | `detection.tool` | `{tool, ok, fields}` (short scalar payload fields only) |
| `sub_call` (analyst) | `detection.analyst.escalation` | `{question, answer}`, plus `error` when the provider refused |
| `result` | `detection.result.done` | `{}` (replay only) |
| `run_end` | `detection.run.completed` | the `DetectionResponse` (live) / `{}` (replay) |

`final` is skipped, so a replay emits exactly one terminal event. A trace with no `run_end` (a hard-killed
run) still ends its replay with a synthesized `detection.run.completed`, so the client never waits forever.
The mapping lives in `diff_sentry_studio/mapper.py`, a pure, unit-tested function and the single source of
truth for the public event surface.

### The live feed is actions-only

diff-sentry's `cli.run` exposes one live observer: the `TraceRecorder`'s `on_event`. The planner's
`main_step` reasoning turns reach it only as a burst after the run finishes, so the live sink forwards
**tool_calls and sub_calls** (scan / deep-classify / ask-analyst / fetch / skill) as they happen and drops
the rest. Planner reasoning is recovered from the stored trace and shown in the **Trajectory drawer**. The
console's feed shows actions only in both live and replay; the replay stream still carries
`detection.plan.step` for other clients.

The studio adds no tool and no callback to the detection path. Streaming live reasoning needs a generic
planner-step observer in **rlm-harness**, available to every consumer, rather than a diff-sentry-specific
hook here.

### Replay order

rlm-harness writes the planner's `main_step` turns after the run, so their `step_id`s trail every live
tool call. The replay endpoint therefore sorts by `ts` (a turn is stamped when its reasoning was parsed),
with `step_id` as the tiebreak and `run_end` pinned last. That restores think-then-act order. A missing,
non-numeric, NaN, or infinite `ts` sorts last instead of making the order depend on input order. A trace
whose turns carry no live stamps clusters them at flush time; the Trajectory drawer reports that as
`per_turn_timing: false`.

## Run

The studio shares ONE venv with the root `diff-sentry`, so every command runs from the **repo root** (the
workspace root).

**Replay-only** (serve and replay stored runs, no diff-sentry runtime needed). The artifacts dir defaults
to `<repo-root>/output`, where a `diff-sentry` CLI run writes, so no `DS_ARTIFACTS_DIR` is needed when you
run both from the repo root:

```bash
uv sync --package diff-sentry-studio          # fastapi + uvicorn into the shared workspace venv
uv run --package diff-sentry-studio uvicorn diff_sentry_studio.app:app --reload
open http://127.0.0.1:8000/                   # paste/PR/issue → live feed → verdict + indicators
curl http://127.0.0.1:8000/v1/runs
uv run pytest studio/tests                    # the contract tests (no server, no diff-sentry needed)
for t in studio/tests/*.test.js; do node "$t"; done   # the node core-tests (zero-dep, pure JS)
```

**Live** (`POST /v1/classify` drives a real classification) needs `diff_sentry` importable and its env
(`DS_ROOT_LM` planner / `DS_SUB_LM` analyst / `DS_CLASSIFIER_LM` classifier / `DS_BASE_URL` …), a Deno
sandbox (`brew install deno`) for the pyodide REPL, and `gh` for `pr`/`issue` ingest. Without
`diff_sentry` the live worker raises `ModuleNotFoundError`; the stream still completes with a `failed`
card, but nothing runs.

`diff-sentry` pins **rlm-harness to an exact PyPI version**, so `uv sync` needs no sibling checkout. To
co-develop rlm-harness locally, overlay it editable (`uv pip install -e ../rlm-harness`).

Do the root env setup first (`cp .env.example .env` and fill it in, see the root `README.md`). The studio
reads `os.environ` directly and does **not** auto-load `.env`, so source it into your shell:

```bash
set -a && source .env && set +a               # DS_ROOT_LM / DS_SUB_LM / DS_CLASSIFIER_LM / DS_BASE_URL … (use `source`, not `.`)
uv run --package diff-sentry-studio --extra live \
  uvicorn diff_sentry_studio.app:app --port 8731 --timeout-graceful-shutdown 12
```

**Subscription mode.** If a role runs on a Claude Pro/Max subscription (`.env` has
`DS_ROOT_LM`/`DS_SUB_LM=claude-agent-sdk/<id>`), the live worker also needs the Claude Agent SDK. Add
`--extra subscription` (it forwards `diff-sentry`'s own `subscription` extra) **to every `uv sync`/`uv
run`**, together with `--extra live` in the **same** command, or a later bare sync prunes the SDK back
out:

```bash
uv run --package diff-sentry-studio --extra live --extra subscription \
  uvicorn diff_sentry_studio.app:app --port 8731 --timeout-graceful-shutdown 12
```

Without it a subscription run raises `ImportError: ClaudeAgentLM requires the optional dependency … No
module named 'claude_agent_sdk'`.

The studio's live runs write to the same artifacts dir as CLI runs, so either can be replayed from the
other. Skip `--reload` for live runs: editing a `.py` restarts the server mid-stream. SIEM emission is
**off** in the studio: the live worker calls `cli.run(..., emit=False)`, so a classification never POSTs a
signal, and the console shows the signal decision and the would-send payload instead.

**No cooperative cancel.** `cli.run` takes no cancel handle, so the studio has no Stop button. A live run
runs to completion, bounded by the RLM's own `max_iterations` (typically seconds to a minute). On Ctrl+C,
uvicorn waits for open SSE streams up to `--timeout-graceful-shutdown`, then exits; the run's worker
thread is a daemon and dies with the process. That can leave a **partial trace and no stored response**
for the run id, which then does not appear in the Load picker.

The frontend is served from the repo checkout (`static/` resolved next to the package). It is a
**zero-build vanilla** page (no node/npm/bundler): `static/{index.html,app.js,style.css,trajectory.js}`
plus the pure, unit-tested `replay-core.js` / `run-core.js` and a vendored JetBrains Mono. The same FastAPI
app serves it same-origin (no CORS): `/static/*` are the assets, `/v1/*` the API. Static assets are served
with `Cache-Control: no-cache`, so a frontend change shows up on the next load without a hard refresh.

## Web frontend (the detection console)

`GET /` is a single page (see `DESIGN.md`):

- **Change.** Paste a change `payload` (or pick a **⚡ hackerbot demo** to load a reconstructed attack), or
  switch to **pr**/**issue** and give `owner/repo` and a number. **Classify** drives a live run; the
  **Load** box replays a stored run id (a `<datalist>` from `GET /v1/runs`). The header holds the role
  chips and a light/dark toggle (persisted, seeded from `prefers-color-scheme`).
- **Detection log.** The SSE feed of actions (scan / deep-classify / ask-analyst / fetch / skill, plus a
  generic row for any other tool), newest at the bottom.
- **The result.** The middle stage is ONE page-height **verdict card** (content scrolls inside it) whose
  alloy is the **derived state, not the verdict**: `alert` (signal **and** ≥high evidence), `amber` (signal
  on softer evidence, or a non-benign verdict with no signal), `clear` (benign, no signal), `iron` (no
  verdict landed). When the planner says `benign` but the evidence forced a signal, a **CONTRADICTION**
  banner states that the deterministic evidence overrode the self-report. A top-right **Verdict /
  Indicators / Change** switch walks the triage order: the call, then **Indicators** (the star view: every
  union hit in a well colored by its severity, with bounded evidence and any base64 decode, reachable on a refusal too),
  then the untrusted diff. The right column holds **Run telemetry**, **Verdict detail** (rationale,
  techniques, suspect files, and any fabricated citations), the **SIEM signal** (the decision and the
  would-send payload, never POSTed), a **Summary** when the run has one, and the **ATLAS rubric**: the
  run's reward-free TF/TA/TG/PA labels from `response.rubric`, each criterion with its deterministic
  observed facts, tagged *labels, not a score*. The rubric shows on a refusal too, since a failed run still
  has a trajectory to label.
- Every `status` is explicit. A `failed`/`inconclusive` run shows an **iron refusal card** with the reason
  and any evidence still gathered, never a blank screen.

Live and replay share one `streamSSE()` (fetch + `ReadableStream`), since native `EventSource` cannot POST.
The **Trajectory** drawer (a bottom sheet, built from `GET /v1/runs/{id}/iterations`) replays the run
iteration by iteration: the planner's REPL turns, a tool timeline (segment width ∝ time), and a transport
to step or play through it.

## Not built yet

- **Cooperative cancel.** Needs a generic run-cancel seam in rlm-harness (see Run).
- **Live planner reasoning.** Needs a generic planner-step observer in rlm-harness (see the live-feed
  section).
- **Wheel-packaged static.** The frontend is served from the repo checkout, the supported run mode. The
  `/` route and the static mount are guarded, so a backend-only install without `static/` still boots.
- **Per-run isolation under concurrency.** The live endpoint runs one job per request in its own thread
  and queue, but concurrent runs share the process CWD and artifacts dir.
